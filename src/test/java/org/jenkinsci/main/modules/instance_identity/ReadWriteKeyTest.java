/*
 * The MIT License
 *
 * Copyright (c) 2016, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.main.modules.instance_identity;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jenkinsci.main.modules.instance_identity.pem.PEMHelper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ReadWriteKeyTest {

    private static Path PEM_PCKS1_FILE;
    private static Path PEM_PCKS8_FILE;
    private static byte[] KEY_PRIVATE_ENCODED;
    private static byte[] KEY_PUBLIC_ENCODED;

    @BeforeAll
    static void setUpBC() throws URISyntaxException, IOException {
        PEM_PCKS1_FILE = Path.of(ReadWriteKeyTest.class
                .getClassLoader()
                .getResource("private-key-pcks1.pem")
                .toURI());
        PEM_PCKS8_FILE = Path.of(ReadWriteKeyTest.class
                .getClassLoader()
                .getResource("private-key-pcks8.pem")
                .toURI());
        KEY_PRIVATE_ENCODED = Files.readAllBytes(Path.of(ReadWriteKeyTest.class
                .getClassLoader()
                .getResource("private-key-private-encoded.bin")
                .toURI()));
        KEY_PUBLIC_ENCODED = Files.readAllBytes(Path.of(ReadWriteKeyTest.class
                .getClassLoader()
                .getResource("private-key-public-encoded.bin")
                .toURI()));
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testReadIdentityPKCS1vsPKCS8() throws Exception {
        String pcks1PEM = Files.readString(PEM_PCKS1_FILE, StandardCharsets.UTF_8);
        String pcks8PEM = Files.readString(PEM_PCKS8_FILE, StandardCharsets.UTF_8);

        KeyPair keyPair1 = PEMHelper.decodePEM(pcks1PEM);
        KeyPair keyPair8 = PEMHelper.decodePEM(pcks8PEM);

        assertArrayEquals(keyPair1.getPrivate().getEncoded(), keyPair8.getPrivate().getEncoded());
        assertArrayEquals(keyPair1.getPublic().getEncoded(), keyPair8.getPublic().getEncoded());
    }

    /**
     * Invalid PEM should throw an IOException
     */
    @Test
    void testDecodeInvalidIdentity() {
        assertThrows(IOException.class, () -> PEMHelper.decodePEM("not valid"));
    }

    /**
     * Invalid PEM should throw an IOException
     */
    @Test
    void testEncodeInvalidIdentity() {
        assertThrows(IOException.class, () -> PEMHelper.encodePEM(new KeyPair(null, null)));
    }

    @Test
    void testWriteIdentityPKCS1vsPKCS8() throws Exception {
        String pcks1PEM = Files.readString(PEM_PCKS1_FILE, StandardCharsets.UTF_8);
        String pcks8PEM = Files.readString(PEM_PCKS8_FILE, StandardCharsets.UTF_8);

        KeyPair keyPair = PEMHelper.decodePEM(pcks8PEM);
        String encodedPEM = PEMHelper.encodePEM(keyPair);

        assertEquals(unifyEOL(pcks1PEM), unifyEOL(encodedPEM));
    }

    @Test
    void testCompareReadPKCS1AndPCKS8() throws Exception {
        String pcks1PEM = Files.readString(PEM_PCKS1_FILE, StandardCharsets.UTF_8);

        KeyPair keyPair = PEMHelper.decodePEM(pcks1PEM);
        String reEncodedPEM = PEMHelper.encodePEM(keyPair);

        assertArrayEquals(keyPair.getPrivate().getEncoded(), KEY_PRIVATE_ENCODED);
        assertArrayEquals(keyPair.getPublic().getEncoded(), KEY_PUBLIC_ENCODED);
        assertEquals(unifyEOL(reEncodedPEM), unifyEOL(Files.readString(PEM_PCKS1_FILE, StandardCharsets.UTF_8)));

        // reread the newly encoded keyPair and retest
        KeyPair keyPair2 = PEMHelper.decodePEM(reEncodedPEM);
        assertArrayEquals(keyPair2.getPrivate().getEncoded(), KEY_PRIVATE_ENCODED);
        assertArrayEquals(keyPair2.getPublic().getEncoded(), KEY_PUBLIC_ENCODED);
    }

    private static String unifyEOL(String s) {
        // unify EOL for comparison purposes
        return s.replaceAll("\r\n", "\n");
    }

}
