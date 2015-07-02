/*
 * The MIT License
 *
 * Copyright 2014 Jesse Glick.
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

import hudson.Util;
import hudson.model.PageDecorator;

import java.io.File;
import java.io.FileInputStream;

import static org.junit.Assert.*;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

public class InstanceIdentityTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    private static final String TEST_IDENTITY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6R6FrlvuyBPstxHKCnRL+oKzEGlgGydD/1Tj/LhCAzgXKnJZFEvo3rrz8CqcWbW3gt04bNXcET9NvAATisR1KP2Zi3EUG/jsXy7q9tr9t0NVAgGC5i5MtU+VFo/te0xAou7nsGng6T/FCXCq1nSeBdfAEQ23+fwyNtJpSbP2EqOrycLox+Xh6M91rt1c3JEHEe/FIrD+NhHQ4m6R/HwWH6DDq8W7P8y9j9/ToVSBBZr0pRETBZre5nkJiwJ/EWnbjqqJ/LguOMTukxPXe8/b9CDFrkuzpYUn8ChtL0DDCE/SoI9jwBSXwj5kQyNoyC9sVrbmEbuAPZ2dRzcDen09CwIDAQAB";

    @LocalData
    @Test public void compatibility() throws Exception {
        assertIdentity();
    }

    @LocalData
    @Test public void reread() throws Exception {
        assertIdentity();
    }

    @LocalData
    @Test public void identityKeyCorrupted() throws Exception {
        String md5CurruptedIdentityKeyFile = "527cb65e89275095a238256b3d31b07a";
        File d = r.jenkins.getRootDir();
        File identityKeyFile = new File(d, "identity.key.enc");

        FileInputStream fis = new FileInputStream(identityKeyFile);
        String md5NewIdentityKeyFile = org.apache.commons.codec.digest.DigestUtils.md5Hex(fis);
        fis.close();
        assertFalse(md5NewIdentityKeyFile.equals(md5CurruptedIdentityKeyFile));
    }

    @LocalData
    @Test
    public void identityKeyNotExist() throws Exception {
        File d = r.jenkins.getRootDir();
        assertTrue(new File(d, "identity.key.enc").isFile());
        assertFalse(new File(d, "identity.key").isFile());
    }

    private void assertIdentity() throws Exception {
        assertEquals(TEST_IDENTITY, r.jenkins.getExtensionList(PageDecorator.class).get(PageDecoratorImpl.class).getEncodedPublicKey());
        File d = r.jenkins.getRootDir();
        assertTrue(new File(d, "identity.key.enc").isFile());
        assertFalse(new File(d, "identity.key").isFile());
    }
}
