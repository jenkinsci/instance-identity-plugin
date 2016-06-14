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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyPair;

import org.apache.commons.io.FileUtils;
import org.jenkinsci.main.modules.instance_identity.pem.PEMHelper;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ReadWriteKeyTest {

    private static File PEM_PCKS1_FILE;
    private static File PEM_PCKS8_FILE;
    private static byte[] KEY_PRIVATE_ENCODED;
    private static byte[] KEY_PUBLIC_ENCODED;
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void setUpBC() throws URISyntaxException, IOException {
        PEM_PCKS1_FILE = new File(
                ReadWriteKeyTest.class.getClassLoader().getResource("private-key-pcks1.pem").toURI());
        PEM_PCKS8_FILE = new File(
                ReadWriteKeyTest.class.getClassLoader().getResource("private-key-pcks8.pem").toURI());
        KEY_PRIVATE_ENCODED = FileUtils.readFileToByteArray(new File(
                ReadWriteKeyTest.class.getClassLoader().getResource("private-key-private-encoded.bin").toURI()));
        KEY_PUBLIC_ENCODED = FileUtils.readFileToByteArray(new File(
                ReadWriteKeyTest.class.getClassLoader().getResource("private-key-public-encoded.bin").toURI()));
    }

    @Test
    public void testReadIdentityPKCS1vsPKCS8() throws Exception {
        String pcks1PEM = FileUtils.readFileToString(PEM_PCKS1_FILE);
        String pcks8PEM = FileUtils.readFileToString(PEM_PCKS8_FILE);

        KeyPair keyPair1 = PEMHelper.decodePEM(pcks1PEM);
        KeyPair keyPair8 = PEMHelper.decodePEM(pcks8PEM);

        assertArrayEquals(keyPair1.getPrivate().getEncoded(), keyPair8.getPrivate().getEncoded());
        assertArrayEquals(keyPair1.getPublic().getEncoded(), keyPair8.getPublic().getEncoded());
    }

    @Test
    public void testWriteIdentityPKCS1vsPKCS8() throws Exception {
        String pcksPEM = FileUtils.readFileToString(PEM_PCKS8_FILE);

        KeyPair keyPair = PEMHelper.decodePEM(pcksPEM);
        String encodedPEM = PEMHelper.encodePEM(keyPair);

        assertEquals(unifyEOL(pcksPEM), unifyEOL(encodedPEM));
    }

    @Test
    public void testCompareReadPKCS1AndPCKS8() throws Exception {
        String pcksPEM = FileUtils.readFileToString(PEM_PCKS1_FILE);

        KeyPair keyPair = PEMHelper.decodePEM(pcksPEM);
        String reEncodedPEM = PEMHelper.encodePEM(keyPair);

        assertArrayEquals(keyPair.getPrivate().getEncoded(), KEY_PRIVATE_ENCODED);
        assertArrayEquals(keyPair.getPublic().getEncoded(), KEY_PUBLIC_ENCODED);
        assertEquals(unifyEOL(reEncodedPEM), unifyEOL(FileUtils.readFileToString(PEM_PCKS8_FILE)));

        // reread the newly encoded keyPair and retest
        KeyPair keyPair2 = PEMHelper.decodePEM(reEncodedPEM);
        assertArrayEquals(keyPair2.getPrivate().getEncoded(), KEY_PRIVATE_ENCODED);
        assertArrayEquals(keyPair2.getPublic().getEncoded(), KEY_PUBLIC_ENCODED);
    }

    private static String unifyEOL(String s) {
        // unify EOL for comparison purposes
        return s.replaceAll("(\r|\n)", "\n");
    }

}
