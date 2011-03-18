package org.jenkinsci.main.modules.instance_identity;

import hudson.model.Hudson;
import hudson.model.PageDecorator;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Captures the RSA key pair that identifies/authenticates this instance.
 *
 * <p>
 * We wrote this for authenticating Jenkins to MetaNectar, but this should be useful
 * wherever we need to authenticate Jenkins against something else.
 *
 * @author Kohsuke Kawaguchi
 */
public class InstanceIdentity {
    private final KeyPair keys;

    public InstanceIdentity() throws IOException {
        this(new File(Hudson.getInstance().getRootDir(), "identity.key"));
    }

    public InstanceIdentity(File keyFile) throws IOException {
        try {
            if (keyFile.exists()) {
                FileReader in = new FileReader(keyFile);
                try {
                    // a hack to work around a problem in PEMReader (or JCE, depending on how you look at it.)
                    // I can't just pass in null as a provider --- JCE doesn't default to the default provider,
                    // but it chokes that I passed in null. Urgh.
                    final String provider = KeyPairGenerator.getInstance("RSA").getProvider().getName();
                    keys = (KeyPair)new PEMReader(in,null,provider).readObject();
                } finally {
                    in.close();
                }
            } else {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048,new SecureRandom()); // going beyond 2048 requires crypto extension
                keys = gen.generateKeyPair();

                PEMWriter w = new PEMWriter(new FileWriter(keyFile),"SunJCE");
                try {
                    w.writeObject(keys);
                } finally {
                    w.close();
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e); // RSA algorithm should be always there
        }
    }

    public RSAPublicKey getPublic() {
        return (RSAPublicKey)keys.getPublic();
    }

    public RSAPrivateKey getPrivate() {
        return (RSAPrivateKey)keys.getPrivate();
    }

    public static InstanceIdentity get() {
        return Hudson.getInstance().getExtensionList(PageDecorator.class).get(PageDecoratorImpl.class).identity;
    }
}
