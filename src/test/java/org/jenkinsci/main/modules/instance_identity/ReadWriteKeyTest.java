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
import java.security.Security;
import java.security.UnrecoverableKeyException;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jenkinsci.main.modules.instance_identity.pem.PEMHelper;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import jenkins.bouncycastle.api.PEMEncodable;

public class ReadWriteKeyTest {

    private static File PEM_PCKS1_FILE;
    private static File PEM_PCKS8_FILE;
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void setUpBC() throws URISyntaxException {
        PEM_PCKS1_FILE = new File(
                ReadWriteKeyTest.class.getClassLoader().getResource("private-key-pcks1.pem").toURI());
        PEM_PCKS8_FILE = new File(
                ReadWriteKeyTest.class.getClassLoader().getResource("private-key-pcks8.pem").toURI());
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
        
        assertEquals(pcksPEM.replace('\n','\r'), encodedPEM.replace('\n','\r')); //to make sure
        
       
    }
    
    @Test
    public void testCompareReadPKCS8WithPEMEncodable() throws Exception {
        String pcksPEM = FileUtils.readFileToString(PEM_PCKS8_FILE);

        KeyPair keyPair = PEMHelper.decodePEM(pcksPEM);
        KeyPair keyPair2 = decodePEMEncodable(pcksPEM);
        String reEncodedPEM = PEMHelper.encodePEM(keyPair);
        
        assertArrayEquals(keyPair.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), keyPair2.getPublic().getEncoded());   
        assertEquals(reEncodedPEM,PEMHelper.encodePEM(keyPair2));

        //reread the nuewly encoded keyPair and retest
        keyPair2 = decodePEMEncodable(reEncodedPEM);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), keyPair2.getPublic().getEncoded());
    }

    @Test
    public void testCompareReadPKCS1WithPEMEncodable() throws Exception {
        String pcksPEM = FileUtils.readFileToString(PEM_PCKS1_FILE);

        KeyPair keyPair = PEMHelper.decodePEM(pcksPEM);
        KeyPair keyPair2 = decodePEMEncodable(pcksPEM);
        String reEncodedPEM = PEMHelper.encodePEM(keyPair);
        
        assertArrayEquals(keyPair.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), keyPair2.getPublic().getEncoded());   
        assertEquals(reEncodedPEM,PEMHelper.encodePEM(keyPair2));

        //reread the nuewly encoded keyPair and retest
        keyPair2 = decodePEMEncodable(reEncodedPEM);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded());
        assertArrayEquals(keyPair.getPublic().getEncoded(), keyPair2.getPublic().getEncoded());
    }

    /**
     * Helper method to execute encode en PEM encodable esuring that BouncyCastle is registered and removed so we don't
     * interfere with the tests ot our methods.
     */
    private String encodePEMEncodable(KeyPair keyPair2) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        String encoded = PEMEncodable.create(keyPair2).encode();
        Security.removeProvider("BC");
        
        return encoded;
    }
    
    /**
     * Helper method to execute decode en PEM encodable esuring that BouncyCastle is registered and removed so we don't
     * interfere with the tests ot our methods.
     */
    private KeyPair decodePEMEncodable(String pcksPEM) throws IOException, UnrecoverableKeyException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair kp = PEMEncodable.decode(pcksPEM).toKeyPair();
        Security.removeProvider("BC");
        
        return kp;
    }
    

    
}
