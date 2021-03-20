package org.littleshoot.proxy.mitm;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CertificateHelper {

    private static final Logger log = LoggerFactory.getLogger(CertificateHelper.class);

    public static final Provider BC_PROVIDER = new BouncyCastleProvider();

    private static final String KEYGEN_ALGORITHM = "RSA";

    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";

    private static final int ROOT_KEYSIZE = 2048;

    private static final int FAKE_KEYSIZE = 2048;

    /** The milliseconds of a day */
    private static final long ONE_DAY = 86400000L;

    /**
     * Current time minus 1 year, just in case software clock goes back due to
     * time synchronization
     */
    private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - ONE_DAY * 365);

    /**
     * The maximum possible value in X.509 specification: 9999-12-31 23:59:59,
     * new Date(253402300799000L), but Apple iOS 8 fails with a certificate
     * expiration date grater than Mon, 24 Jan 6084 02:07:59 GMT (issue #6).
     * 
     * Hundred years in the future from starting the proxy should be enough.
     */
    private static final Date NOT_AFTER = new Date(System.currentTimeMillis() + ONE_DAY * 365 * 100);

    private static final String TLSV_1_3 = "TLSv1.3";
    private static final String TLSV_1_2 = "TLSv1.2";

    private CertificateHelper() {}

    public static KeyPair generateKeyPair(int keySize) {
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance(KEYGEN_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(String.format("Key generation algorithm ''%s not supported.", KEYGEN_ALGORITHM), e);
        }
        generator.initialize(keySize, new SecureRandom());
        return generator.generateKeyPair();
    }

    public static KeyStore createRootCertificate(Authority authority,
            String keyStoreType)  {
        try {
            KeyPair keyPair = generateKeyPair(ROOT_KEYSIZE);
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            nameBuilder.addRDN(BCStyle.CN, authority.getCommonName());
            nameBuilder.addRDN(BCStyle.O, authority.getOrganization());
            nameBuilder.addRDN(BCStyle.OU, authority.getCertOrganization());

            X500Name issuer = nameBuilder.build();
            BigInteger serial = BigInteger.valueOf(initRandomSerial());
            X500Name subject = issuer;
            PublicKey pubKey = keyPair.getPublic();

            X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(
                    issuer, serial, NOT_BEFORE, NOT_AFTER, subject, pubKey);

            generator.addExtension(Extension.subjectKeyIdentifier, false,
                    createSubjectKeyIdentifier(pubKey));
            generator.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(true));

            KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign
                    | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                    | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
            generator.addExtension(Extension.keyUsage, false, usage);

            ASN1EncodableVector purposes = new ASN1EncodableVector();
            purposes.add(KeyPurposeId.id_kp_serverAuth);
            purposes.add(KeyPurposeId.id_kp_clientAuth);
            purposes.add(KeyPurposeId.anyExtendedKeyUsage);
            generator.addExtension(Extension.extendedKeyUsage, false,
                    new DERSequence(purposes));

            X509Certificate cert = signCertificate(generator, keyPair.getPrivate());

            KeyStore result = KeyStore.getInstance(keyStoreType, BC_PROVIDER);
            result.load(null, null);
            result.setKeyEntry(authority.getAlias(), keyPair.getPrivate(),
                    authority.getPassword(), new Certificate[]{cert});
            return result;
        }
        catch (Exception e) {
            throw new RuntimeException("Could not create root certificate.", e);
        }
    }

    private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) {
        ByteArrayInputStream bIn = new ByteArrayInputStream(key.getEncoded());
        try {
            try (ASN1InputStream is = new ASN1InputStream(bIn)) {
                ASN1Sequence seq = (ASN1Sequence) is.readObject();
                SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(seq);
                return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
            }
        }
        catch (Exception e) {
            throw new RuntimeException("Could not create subject key identifier.", e);
        }
    }

    public static KeyStore createServerCertificate(String commonName,
            SubjectAlternativeNameHolder subjectAlternativeNames,
            Authority authority, Certificate caCert, PrivateKey caPrivKey) {

        try {
            KeyPair keyPair = generateKeyPair(FAKE_KEYSIZE);

            X500Name issuer = new X509CertificateHolder(caCert.getEncoded())
                    .getSubject();
            BigInteger serial = BigInteger.valueOf(initRandomSerial());

            X500NameBuilder name = new X500NameBuilder(BCStyle.INSTANCE);
            name.addRDN(BCStyle.CN, commonName);
            name.addRDN(BCStyle.O, authority.getCertOrganization());
            name.addRDN(BCStyle.OU, authority.getCertOrganizationalUnitName());
            X500Name subject = name.build();

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, NOT_BEFORE,
                    new Date(System.currentTimeMillis() + ONE_DAY), subject, keyPair.getPublic());

            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.basicConstraints, false,
                    new BasicConstraints(false));

            subjectAlternativeNames.fillInto(builder);

            X509Certificate cert = signCertificate(builder, caPrivKey);

            cert.checkValidity(new Date());
            cert.verify(caCert.getPublicKey());

            KeyStore result = KeyStore.getInstance("PKCS12", BC_PROVIDER);
            result.load(null, null);
            Certificate[] chain = {cert, caCert};
            result.setKeyEntry(authority.getAlias(), keyPair.getPrivate(),
                    authority.getPassword(), chain);

            return result;
        }
        catch (Exception e) {
            throw new RuntimeException("Could not create server certificate.", e);
        }
    }

    private static X509Certificate signCertificate(
            X509v3CertificateBuilder certificateBuilder,
            PrivateKey signedWithPrivateKey)  {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                    .setProvider(BC_PROVIDER).build(signedWithPrivateKey);
            return new JcaX509CertificateConverter().setProvider(
                    BC_PROVIDER).getCertificate(certificateBuilder.build(signer));
        }
        catch (Exception e) {
            throw new RuntimeException("Could not sign certificate.", e);
        }
    }

    public static KeyManager[] getKeyManagers(KeyStore keyStore,
            Authority authority) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, authority.getPassword());
            return kmf.getKeyManagers();
        }
        catch (Exception e) {
            throw new RuntimeException("Could not create key manager.", e);
        }
    }

    public static SSLContext newClientContext(KeyManager[] keyManagers,
            TrustManager[] trustManagers) {
        try {
            SSLContext result = newSSLContext();
            result.init(keyManagers, trustManagers, new SecureRandom());
            return result;
        }
        catch (Exception e) {
            throw new RuntimeException("Could not create key manager.", e);
        }
    }

    public static SSLContext newServerContext(KeyManager[] keyManagers) {
        try {
            SSLContext result = newSSLContext();
            SecureRandom random = new SecureRandom();
            result.init(keyManagers, null, random);
            return result;
        }
        catch (Exception e) {
            throw new RuntimeException("Could not create SSL context.", e);
        }
    }

    private static boolean isAndroid() {
        try {
            Class.forName("android.content.Context");
            return true;
        }
        catch (ClassNotFoundException e) {
            return false;
        }
    }

    private static SSLContext newSSLContext() {
        try {
            log.debug("Using protocol {}", TLSV_1_3);
            if (isAndroid()) {
                return SSLContext.getInstance(TLSV_1_3);
            }
            return SSLContext.getInstance(TLSV_1_3, org.conscrypt.Conscrypt.newProvider());
        } catch (NoSuchAlgorithmException e) {
            log.debug("Protocol {} not available, falling back to {}", TLSV_1_3, TLSV_1_2);
            try {
                log.debug("Using protocol {}", TLSV_1_2);
                if (isAndroid()) {
                    return SSLContext.getInstance(TLSV_1_2);
                }
                return SSLContext.getInstance(TLSV_1_2, org.conscrypt.Conscrypt.newProvider());
            } catch (NoSuchAlgorithmException e2) {
                throw new RuntimeException(String.format("TLS protocol %s not available", TLSV_1_2), e2);
            }
        }
    }

    public static long initRandomSerial() {
        final Random rnd = new Random();
        rnd.setSeed(System.currentTimeMillis());
        // prevent browser certificate caches, cause of doubled serial numbers
        // using 48bit random number
        long sl = ((long) rnd.nextInt()) << 32 | (rnd.nextInt() & 0xFFFFFFFFL);
        // let reserve of 16 bit for increasing, serials have to be positive
        sl = sl & 0x0000FFFFFFFFFFFFL;
        return sl;
    }

}
