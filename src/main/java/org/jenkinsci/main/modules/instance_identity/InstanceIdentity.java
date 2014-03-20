package org.jenkinsci.main.modules.instance_identity;

import hudson.FilePath;
import hudson.Util;
import hudson.model.PageDecorator;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import jenkins.model.Jenkins;
import jenkins.security.HexStringConfidentialKey;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;

/**
 * Captures the RSA key pair that identifies/authenticates this instance.
 * Useful wherever we need to authenticate Jenkins against something external to it ({@code sshd-module} for example).
 *
 * @author Kohsuke Kawaguchi
 */
public class InstanceIdentity {
    private final KeyPair keys;

    public InstanceIdentity() throws IOException {
        this(new File(Jenkins.getInstance().getRootDir(), "identity.pem"), new File(Jenkins.getInstance().getRootDir(), "identity.key"));
    }

    public InstanceIdentity(File keyFile) throws IOException {
        this(keyFile, null);
    }

    InstanceIdentity(File keyFile, File oldKeyFile) throws IOException {
        KeyPairGenerator gen;
        Cipher cipher;
        try {
            gen = KeyPairGenerator.getInstance("RSA");
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (Exception e) {
            throw new AssertionError(e); // RSA algorithm should be always there
        }

        if (oldKeyFile.exists()) {
            FileReader in = new FileReader(oldKeyFile);
            try {
                // a hack to work around a problem in PEMReader (or JCE, depending on how you look at it.)
                // I can't just pass in null as a provider --- JCE doesn't default to the default provider,
                // but it chokes that I passed in null. Urgh.
                String provider = gen.getProvider().getName();
                keys = (KeyPair)new PEMReader(in,null,provider).readObject();
            } finally {
                in.close();
            }
            write(keys, keyFile);
            Util.deleteFile(oldKeyFile);
        } else if (keyFile.exists()) {
            FileReader in = new FileReader(keyFile);
            try {
                String provider = cipher.getProvider().getName();
                keys = (KeyPair) new PEMReader(in, new PasswordFinderImpl(), provider, gen.getProvider().getName()).readObject();
            } finally {
                in.close();
            }
        } else {
            gen.initialize(2048,new SecureRandom()); // going beyond 2048 requires crypto extension
            keys = gen.generateKeyPair();
            write(keys, keyFile);
        }
    }

    private static void write(KeyPair keys, File keyFile) throws IOException {
        PEMWriter w = new PEMWriter(new FileWriter(keyFile), "SunJCE");
        try {
            w.writeObject(keys, "AES-128-CBC", new PasswordFinderImpl().getPassword(), new SecureRandom());
        } finally {
            w.close();
        }
        makeReadOnly(keyFile);
    }

    private static final class PasswordFinderImpl implements PasswordFinder {
        public char[] getPassword() {
            return KEY.get().toCharArray();
        }
    }

    private static final HexStringConfidentialKey KEY = new HexStringConfidentialKey(InstanceIdentity.class, "KEY", 64);

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
