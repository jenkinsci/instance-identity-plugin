package org.jenkinsci.main.modules.instance_identity;

import hudson.Extension;
import hudson.model.PageDecorator;
import java.io.IOException;

/**
 * Advertises the public key.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class PageDecoratorImpl extends PageDecorator {
    public final InstanceIdentity identity;

    public PageDecoratorImpl() throws IOException {
        super();
        this.identity = new InstanceIdentity();
    }

    public String getEncodedPublicKey() {
        return identity.getEncodedPublicKey();
    }
}
