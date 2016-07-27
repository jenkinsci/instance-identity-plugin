package org.jenkinsci.main.modules.instance_identity;

import hudson.Extension;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import jenkins.model.identity.InstanceIdentityProvider;

/**
 * Implementation of {@link InstanceIdentityProvider} for {@link InstanceIdentityProvider#RSA}.
 *
 * @since 2.1
 */
@Extension
public class InstanceIdentityRSAProvider extends InstanceIdentityProvider<RSAPublicKey, RSAPrivateKey> {

    /**
     * {@inheritDoc}
     */
    @Override
    protected KeyPair getKeyPair() {
        InstanceIdentity identity = InstanceIdentity.get();
        return new KeyPair(identity.getPublic(), identity.getPrivate());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected RSAPublicKey getPublicKey() {
        return InstanceIdentity.get().getPublic();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected RSAPrivateKey getPrivateKey() {
        return InstanceIdentity.get().getPrivate();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected X509Certificate getCertificate() {
        return InstanceIdentity.get().getCertificate();
    }
}
