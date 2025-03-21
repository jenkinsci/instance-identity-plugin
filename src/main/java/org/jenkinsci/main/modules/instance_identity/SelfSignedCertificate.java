package org.jenkinsci.main.modules.instance_identity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class SelfSignedCertificate {

    private final KeyPair keyPair;
    private Date firstDate = new Date();
    private Date lastDate = new Date(firstDate.getTime() + TimeUnit.DAYS.toMillis(365));
    private X500NameBuilder subject = new X500NameBuilder(BCStyle.INSTANCE);
    private String hashAlg = "SHA1";

    private SelfSignedCertificate(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public static SelfSignedCertificate forKeyPair(KeyPair keyPair) {
        return new SelfSignedCertificate(keyPair);
    }

    public SelfSignedCertificate validFrom(Date date) {
        this.firstDate = date == null ? new Date() : (Date) (date.clone());
        return this;
    }

    public SelfSignedCertificate validUntil(Date date) {
        this.lastDate =
                date == null ? new Date(firstDate.getTime() + TimeUnit.DAYS.toMillis(365)) : (Date) (date.clone());
        return this;
    }

    public SelfSignedCertificate cn(String name) {
        subject.addRDN(BCStyle.CN, name);
        return this;
    }

    public SelfSignedCertificate c(String name) {
        subject.addRDN(BCStyle.C, name);
        return this;
    }

    public SelfSignedCertificate o(String name) {
        subject.addRDN(BCStyle.O, name);
        return this;
    }

    public SelfSignedCertificate ou(String name) {
        subject.addRDN(BCStyle.OU, name);
        return this;
    }

    public SelfSignedCertificate oid(String oid, String name) {
        subject.addRDN(new ASN1ObjectIdentifier(oid), name);
        return this;
    }

    public SelfSignedCertificate sha1() {
        hashAlg = "SHA1";
        return this;
    }

    public SelfSignedCertificate sha224() {
        hashAlg = "SHA224";
        return this;
    }

    public SelfSignedCertificate sha256() {
        hashAlg = "SHA256";
        return this;
    }

    public SelfSignedCertificate sha384() {
        hashAlg = "SHA384";
        return this;
    }

    public SelfSignedCertificate sha512() {
        hashAlg = "SHA512";
        return this;
    }

    public X509Certificate generate() throws IOException {
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo =
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

            X500Name subject = this.subject.build();

            X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                    subject,
                    BigInteger.ONE,
                    firstDate,
                    lastDate,
                    subject,
                    subjectPublicKeyInfo
            );

            JcaX509ExtensionUtils instance = new JcaX509ExtensionUtils();

            certGen.addExtension(Extension.subjectKeyIdentifier,
                    false,
                    instance.createSubjectKeyIdentifier(subjectPublicKeyInfo)
            );

            ContentSigner signer;
            if (keyPair.getPrivate() instanceof RSAPrivateKey) {
                signer = new JcaContentSignerBuilder(hashAlg + "withRSA").build(keyPair.getPrivate());
            } else if (keyPair.getPrivate() instanceof DSAPrivateKey) {
                signer = new JcaContentSignerBuilder(hashAlg + "withDSA").build(keyPair.getPrivate());
            } else if (keyPair.getPrivate() instanceof ECPrivateKey) {
                signer = new JcaContentSignerBuilder(hashAlg + "withECDSA").build(keyPair.getPrivate());
            } else {
                throw new IOException("Unsupported key type");
            }

            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certGen.build(signer).getEncoded()));
        } catch (OperatorCreationException | CertificateException | NoSuchAlgorithmException e) {
            throw new IOException("Failed to generate a certificate", e);
        }
    }
}
