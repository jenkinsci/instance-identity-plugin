package org.jenkinsci.main.modules.instance_identity;

import hudson.Extension;
import hudson.model.PageDecorator;
import java.nio.charset.Charset;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;

/**
 * Advertises the public key.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class PageDecoratorImpl extends PageDecorator {
    public final InstanceIdentity identity;

    public PageDecoratorImpl() throws IOException {
        super(PageDecoratorImpl.class);
        this.identity = new InstanceIdentity();
    }

    public String getEncodedPublicKey() {
        RSAPublicKey key = identity.getPublic();
        return new String(Base64.encodeBase64(key.getEncoded()), Charset.forName("UTF-8"));
    }
}
