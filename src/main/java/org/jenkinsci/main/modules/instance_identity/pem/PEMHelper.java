package org.jenkinsci.main.modules.instance_identity.pem;

import java.io.IOException;
import java.security.KeyPair;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.umd.cs.findbugs.annotations.NonNull;

import jenkins.bouncycastle.api.PEMEncodable;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Helper class to decode and encode PEM formatted strings using {@link PEMEncodable}
 *
 * @see PEMEncodable
 * @see PEMEncodable#encode()
 * @see PEMEncodable#decode(String, char[])
 */
@Restricted(NoExternalUse.class)
public class PEMHelper {

    /**
     * Decodes a PEM formatted string to {@link KeyPair}. Wrapper for {@link PEMEncodable#decode(String)}.
     * 
     * @param pem {@link String} with the PEM format
     * @return decoded PEM as {@link KeyPair}
     * @throws IOException if a problem exists decoding the PEM
     * @see PEMEncodable#decode(String, char[])
     */
    @NonNull
    public static KeyPair decodePEM(@NonNull String pem) throws IOException {
        try {
            final PEMEncodable decode = PEMEncodable.decode(pem);
            KeyPair keyPair = decode.toKeyPair();
            if (keyPair != null) {
                return keyPair;
            } else {
                final Object rawObject = decode.getRawObject();
                String received;
                if (rawObject != null) {
                    received = rawObject.getClass().getName();
                } else {
                    received = "null";
                }
                LOGGER.log(Level.SEVERE,
                        "Error reading private key, obtained unexpected result. Received {0} when expecting {1}",
                        new Object[]{received, RSAPrivateCrtKey.class.getName()});
                throw new IOException("Error reading private key, obtained unexpected result.");
            }

        } catch (UnrecoverableKeyException e) {
            LOGGER.log(Level.SEVERE, "Error reading private key, obtained unexpected result.", e);
            throw new IOException("Error reading private key, obtained unexpected result.");
        }
    }

    /**
     * Encodes a {@link KeyPair} in a PCKS1 PEM formatted string. Wrapper for {@link PEMEncodable#encode()}.
     *
     * @param keys {@link KeyPair} to encode
     * @return {@link KeyPair} as an encoded PEM String
     * @throws IOException if a problem exists decoding the PEM
     * @see PEMEncodable#encode()
     */
    @NonNull
    public static String encodePEM(@NonNull KeyPair keys) throws IOException {
        try {
            final PEMEncodable pemEncodable = PEMEncodable.create(keys.getPrivate());
            return pemEncodable.encode();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error writing private key, obtained unexpected result.", e);
            throw new IOException("Error writing private key, obtained unexpected result.");
        }
    }

    private static final Logger LOGGER = Logger.getLogger(PEMHelper.class.getName());
}
