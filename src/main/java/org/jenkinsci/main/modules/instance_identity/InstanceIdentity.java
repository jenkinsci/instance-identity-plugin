package org.jenkinsci.main.modules.instance_identity;

import hudson.FilePath;
import hudson.Util;
import hudson.model.PageDecorator;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.jenkinsci.main.modules.instance_identity.pem.PEMHelper;

import jenkins.model.Jenkins;
import jenkins.security.CryptoConfidentialKey;

/**
 * Captures the RSA key pair that identifies/authenticates this instance.
 * Useful wherever we need to authenticate Jenkins against something external to it ({@code sshd-module} for example).
 *
 * @author Kohsuke Kawaguchi
 */
public class InstanceIdentity {
    private final KeyPair keys;

    public InstanceIdentity() throws IOException {
        this(new File(Jenkins.getInstance().getRootDir(), "identity.key.enc"), new File(Jenkins.getInstance().getRootDir(), "identity.key"));
    }

    public InstanceIdentity(File keyFile) throws IOException {
        this(keyFile, null);
    }

    InstanceIdentity(File keyFile, File oldKeyFile) throws IOException {
        KeyPairGenerator gen;
        try {
            gen = KeyPairGenerator.getInstance("RSA");
        } catch (Exception e) {
            throw new AssertionError(e); // RSA algorithm should be always there
        }
        if (oldKeyFile!= null && oldKeyFile.exists()) { //Process old KeyFile
            keys = read(null, oldKeyFile, gen);
            write(keys, keyFile);
            Util.deleteFile(oldKeyFile);
        } else { //Process KeyFile
            KeyPair tempKeys = read(keyFile, null, gen);
            if(tempKeys!=null) { //Assign the KeyPair in case the read is successful
                keys = tempKeys;
            } else { //Generate a new KeyFile in case it doesn't exist or it is corrupted
                gen.initialize(2048, new SecureRandom()); // going beyond 2048 requires crypto extension
                keys = gen.generateKeyPair();
                write(keys, keyFile);
            }
        }
    }

    private static KeyPair read(File keyFile, File oldKeyFile, KeyPairGenerator gen) throws IOException {
        byte[] enc;
        KeyPair keyPair = null;

        if (keyFile != null) { //Get the Reader for keyFile and handle if corrupted
            try {
                enc = FileUtils.readFileToByteArray(keyFile);
                keyPair = PEMHelper.decodePEM(new String(KEY.decrypt().doFinal(enc), "UTF-8"));
            } catch (FileNotFoundException e) {
                LOGGER.fine("identity.key.enc doesn't exist. New Identity.key.enc will be generated");
                return null;
            } catch (GeneralSecurityException x) {
                LOGGER.log(Level.SEVERE, "identity.key.enc is corrupted. Identity.key.enc will be deleted and a new one will be generated", x);
                return null;
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "failed to access identity.key.enc. Identity.key.enc will be deleted and a new one will be generated", e);
                return null;
            }
        } else if (oldKeyFile != null) { //Get the Reader for oldKeyFile
            keyPair = PEMHelper.decodePEM(FileUtils.readFileToString(oldKeyFile));
        }
        return keyPair;
    }

    private static void write(KeyPair keys, File keyFile) throws IOException {
        String pem = PEMHelper.encodePEM(keys);
        OutputStream os = new FileOutputStream(keyFile);
        try {
            os.write(KEY.encrypt().doFinal(pem.getBytes("UTF-8")));
        } catch (GeneralSecurityException x) {
            throw new IOException(x);
        } finally {
            os.close();
        }
        makeReadOnly(keyFile);
    }

    // Would be neater to actually write an encrypted RSA key in PEM format, but could not wrangle BouncyCastle into reading the result, so just doing generic encryption instead:
    private static final CryptoConfidentialKey KEY = new CryptoConfidentialKey(InstanceIdentity.class, "KEY");

    /**
     * Try to make the key read-only.
     */
    private static void makeReadOnly(File keyFile) {
        try {
            new FilePath(keyFile).chmod(0600);
        } catch (Throwable e) {
            LOGGER.log(Level.WARNING, "Failed to make read only: "+keyFile,e);
        }
    }

    public RSAPublicKey getPublic() {
        return (RSAPublicKey)keys.getPublic();
    }

    public RSAPrivateKey getPrivate() {
        return (RSAPrivateKey)keys.getPrivate();
    }

    public static InstanceIdentity get() {
        return Jenkins.getInstance().getExtensionList(PageDecorator.class).get(PageDecoratorImpl.class).identity;
    }

    private static final Logger LOGGER = Logger.getLogger(InstanceIdentity.class.getName());
}
