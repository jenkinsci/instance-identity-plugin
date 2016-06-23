package org.jenkinsci.main.modules.instance_identity.pem;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Helper class to decode an encode PEM formated strings without any external dependencies
 * The supported formats are:
 * <ul>
 * <li> PCKS8 encode and decode
 * <li> PCKS1 only decode
 * </ul>
 */
@Restricted(NoExternalUse.class)
public class PEMHelper {

    private static final String BEGIN_RSA_PK = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String END_RSA_PK = "-----END RSA PRIVATE KEY-----";
    private static final String BEGIN_PK = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PK = "-----END PRIVATE KEY-----";
    private static final String PEM_LINE_SEP = "\n";
    private static final int PEM_LINE_LENGTH = 64;

    /**
     * Decodes a PEM formated string to {@link KeyPair}. Only PCKS1 and PCKS8 formats are supported
     * 
     * @param pem {@link String} with the PEM format
     * @return decoded PEM as {@link KeyPair}
     * @throws IOException if a problem exists decoding the PEM 
     */
    @Nonnull
    public static KeyPair decodePEM(@Nonnull String pem) throws IOException {
        KeySpec privKeySpec;

        // obtain KeySpec according to the detected format
        if (pem.startsWith(BEGIN_RSA_PK)) { // PCKS1
            byte[] binaryPem = extractBinaryPEM(pem, BEGIN_RSA_PK, END_RSA_PK);
            privKeySpec = newRSAPrivateCrtKeySpec(binaryPem);
        } else if (pem.startsWith(BEGIN_PK)) { // PCKS8
            byte[] binaryPem = extractBinaryPEM(pem, BEGIN_PK, END_PK);
            privKeySpec = new PKCS8EncodedKeySpec(binaryPem);
        } else {
            throw new IOException("Could not read PEM file incorrect header.");
        }

        try {
            //obtain the private key from the spec
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privKey = kf.generatePrivate(privKeySpec);

            if (privKey instanceof RSAPrivateCrtKey) {
                //obtain public key spec from the private key
                RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privKey;
                RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(),
                                                                   rsaPrivateKey.getPublicExponent());
                return new KeyPair(kf.generatePublic(pubKeySpec), privKey);
            } else {
                LOGGER.log(Level.SEVERE,
                        "Error reading private key, obtained unexpected result. Received {0} when expecting {1}",
                        new Object[] { privKey.getClass().getName(), RSAPrivateCrtKey.class.getName() });
                throw new IOException("Error reading private key, obtained unexpected result.");
            }

        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(
                    "RSA algorithm support is mandated by Java Language Specification. See https://docs.oracle.com/javase/7/docs/api/java/security/KeyFactory.html");
        } catch (InvalidKeySpecException e) {
            throw new IOException("Invalid key specification: " + e.getMessage());
        }
    }
    
    /**
     * Encodes a {@link KeyPair} in a PCKS8 PEM formated string.
     * 
     * @param keys {@link KeyPair} to encode
     * @return {@link KeyPair} as an encoded PEM String 
     * @throws IOException if a problem exists decoding the PEM 
     */
    @Nonnull
    public static String encodePEM(@Nonnull KeyPair keys) throws IOException {

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            BufferedWriter bw = new BufferedWriter(new PrintWriter(baos));

            bw.write(BEGIN_PK);
            bw.write(PEM_LINE_SEP);

            writeEncoded(keys.getPrivate().getEncoded(), bw);

            bw.write(END_PK);
            bw.write(PEM_LINE_SEP);
            bw.close();

            return baos.toString(StandardCharsets.UTF_8.name());
        } catch (AssertionError e) {
            throw new AssertionError(
                    "UTF-8 character set support is mandated by Java Language Specification. See https://docs.oracle.com/javase/7/docs/api/java/nio/charset/StandardCharsets.html");
        }
    }
    
    private static byte[] extractBinaryPEM(String pem, String header, String footer) {
        String stripedPEM = StringUtils.stripEnd(StringUtils.strip(pem, header), header);
        // sanity cleanup
        stripedPEM = stripedPEM.replaceAll("(\r|\n|\t| )", "");
        return DatatypeConverter.parseBase64Binary(stripedPEM);
    }

    /**
     * Convert PKCS#1 encoded private key into RSAPrivateCrtKeySpec.
     * 
     * <p/>
     * The ASN.1 syntax for the private key with CRT is
     * 
     * <pre>
     * -- 
     * -- Representation of RSA private key with information for the CRT algorithm.
     * --
     * RSAPrivateKey ::= SEQUENCE {
     *   version           Version, 
     *   modulus           INTEGER,  -- n
     *   publicExponent    INTEGER,  -- e
     *   privateExponent   INTEGER,  -- d
     *   prime1            INTEGER,  -- p
     *   prime2            INTEGER,  -- q
     *   exponent1         INTEGER,  -- d mod (p-1)
     *   exponent2         INTEGER,  -- d mod (q-1) 
     *   coefficient       INTEGER,  -- (inverse of q) mod p
     *   otherPrimeInfos   OtherPrimeInfos OPTIONAL 
     * }
     * </pre>
     *  See p.41 of http://www.emc.com/emc-plus/rsa-labs/pkcs/files/h11300-wp-pkcs-1v2-2-rsa-cryptography-standard.pdf
     * @param keyInPkcs1 PKCS#1 encoded key
     * @throws IOException
     */
    private static RSAPrivateCrtKeySpec newRSAPrivateCrtKeySpec(byte[] keyInPkcs1) throws IOException {

        DerParser parser = new DerParser(keyInPkcs1);
        Asn1Object sequence = parser.read();
        if (sequence.getType() != DerParser.SEQUENCE)
            throw new IllegalArgumentException("Invalid DER: not a sequence");

        // Parse inside the sequence
        DerParser seqParser = sequence.getParser();

        seqParser.read(); // Skip version
        BigInteger modulus = seqParser.read().getInteger();
        BigInteger publicExp = seqParser.read().getInteger();
        BigInteger privateExp = seqParser.read().getInteger();
        BigInteger prime1 = seqParser.read().getInteger();
        BigInteger prime2 = seqParser.read().getInteger();
        BigInteger exp1 = seqParser.read().getInteger();
        BigInteger exp2 = seqParser.read().getInteger();
        BigInteger crtCoef = seqParser.read().getInteger();

        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1,
                exp2, crtCoef);

        return keySpec;
    }

    private static void writeEncoded(byte[] bytes, BufferedWriter wr) throws IOException {
        char[] buf = new char[PEM_LINE_LENGTH];
        bytes = DatatypeConverter.printBase64Binary(bytes).getBytes();
        for (int i = 0; i < bytes.length; i += buf.length) {
            int index;
            for (index = 0; index < buf.length && (i + index) < bytes.length; index++) {
                buf[index] = (char) bytes[i + index];
            }
            wr.write(buf, 0, index);
            wr.write(PEM_LINE_SEP);
        }
    }

    private static final Logger LOGGER = Logger.getLogger(PEMHelper.class.getName());
}