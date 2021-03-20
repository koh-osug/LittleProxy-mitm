package org.littleshoot.proxy.mitm;

import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.littleshoot.proxy.SslEngineSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * A {@link SslEngineSource} which creates a key store with a Root Certificate
 * Authority. The certificates are generated lazily if the given key store file
 * doesn't yet exist.
 * <p>
 * The root certificate is exported in PEM format to be used in a browser. The
 * proxy application presents for every host a dynamically created certificate
 * to the browser, signed by this certificate authority.
 * <p>
 * This facilitates the proxy to handle as a "Man In The Middle" to filter the
 * decrypted content in clear text.
 * <p>
 * The hard part was done by mawoki. It's derived from Zed Attack Proxy (ZAP).
 * ZAP is an HTTP/HTTPS proxy for assessing web application security. Copyright
 * 2011 mawoki@ymail.com Licensed under the Apache License, Version 2.0
 */
public class MitmSslEngineSource implements SslEngineSource {

    private static final Logger LOG = LoggerFactory.getLogger(MitmSslEngineSource.class);

    private static final String KEY_STORE_TYPE = "PKCS12";

    private static final String KEY_STORE_FILE_EXTENSION = ".p12";

    private static final String CERT_FILE_EXTENSION = ".pem";

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    private final Authority authority;

    private final boolean trustAllServers;

    private final KeyStore additionalTrustStore;

    private final KeyManagerFactory kmf;

    private SSLContext sslContext;

    private Certificate caCert;

    private PrivateKey caPrivKey;

    private final Cache<String, SSLContext> serverSSLContexts;

    /**
     * Creates a SSL engine source create a Certificate Authority if needed and
     * initializes a SSL context. Exceptions will be thrown to let the manager
     * decide how to react. Don't install a MITM manager in the proxy in case of
     * a failure.
     *
     * @param authority       a parameter object to provide personal information of the
     *                        Certificate Authority and the dynamic certificates.
     * @param trustAllServers <code>true</code> to trust all server certificates.
     * @param kmf The key manager factory for client certificates.
     * @param additionalTrustStore Additional trust store for certificates.
     * @param sslContexts     a cache to store dynamically created server certificates.
     *                        Generation takes between 50 to 500ms, but only once per
     *                        thread, since there is a connection cache too. It's save to
     *                        give a null cache to prevent memory or locking issues.
     */
    public MitmSslEngineSource(Authority authority,
                               boolean trustAllServers, KeyManagerFactory kmf,
                               KeyStore additionalTrustStore,
                               Cache<String, SSLContext> sslContexts) {
        this.authority = authority;
        this.trustAllServers = trustAllServers;
        this.additionalTrustStore = additionalTrustStore;
        this.kmf = kmf;
        this.serverSSLContexts = sslContexts;
        initializeKeyStore();
        initializeSSLContext();
    }

    /**
     * Creates a SSL engine source create a Certificate Authority if needed and
     * initializes a SSL context. This constructor defaults a cache to store
     * dynamically created server certificates. Exceptions will be thrown to let
     * the manager decide how to react. Don't install a MITM manager in the
     * proxy in case of a failure.
     *
     * @param authority       a parameter object to provide personal informations of the
     *                        Certificate Authority and the dynamic certificates.
     * @param trustAllServers code>true</code> to trust all server certificates.
     * @param kmf The key manager factory for client certificates.
     * @param additionalTrustStore Additional trust store for certificates.
     */
    public MitmSslEngineSource(Authority authority,
                               boolean trustAllServers, KeyManagerFactory kmf,
                               KeyStore additionalTrustStore) {
        this(authority, trustAllServers, kmf, additionalTrustStore,
                initDefaultCertificateCache());
    }

    private static Cache<String, SSLContext> initDefaultCertificateCache() {
        return CacheBuilder.newBuilder() //
                .expireAfterAccess(5, TimeUnit.MINUTES) //
                .concurrencyLevel(16) //
                .build();
    }

    public SSLEngine newSslEngine() {
        return sslContext.createSSLEngine();
    }

    @Override
    public SSLEngine newSslEngine(String remoteHost, int remotePort) {
        LOG.info("Creating SSL engine for host '{}'", remoteHost);
        SSLEngine sslEngine = sslContext
                .createSSLEngine(remoteHost, remotePort);
        sslEngine.setUseClientMode(true);
        SSLParameters sslParams = new SSLParameters();
        sslParams.setEndpointIdentificationAlgorithm("HTTPS");
        sslEngine.setSSLParameters(sslParams);
        return sslEngine;
    }

    private void initializeKeyStore() {
        if (authority.aliasFile(KEY_STORE_FILE_EXTENSION).exists()
                && authority.aliasFile(CERT_FILE_EXTENSION).exists()) {
            return;
        }
        MillisecondsDuration duration = new MillisecondsDuration();
        KeyStore keystore = CertificateHelper.createRootCertificate(authority, KEY_STORE_TYPE);
        LOG.info("Created root certificate authority key store in {}ms", duration);
        try {
            try (OutputStream os = new FileOutputStream(
                    authority.aliasFile(KEY_STORE_FILE_EXTENSION))) {
                keystore.store(os, authority.getPassword());
            }

            Certificate cert = keystore.getCertificate(authority.getAlias());
            exportPem(authority.aliasFile(CERT_FILE_EXTENSION), cert);
        } catch (Exception e) {
            throw new RuntimeException("Could not initialize key store.", e);
        }
    }

    private void initializeSSLContext() {
        try {
            KeyStore ks = loadKeyStore();
            caCert = ks.getCertificate(authority.getAlias());
            caPrivKey = (PrivateKey) ks.getKey(authority.getAlias(),
                    authority.getPassword());

            TrustManager[] trustManagers;
            if (trustAllServers) {
                trustManagers = InsecureTrustManagerFactory.INSTANCE
                        .getTrustManagers();
            } else {
                trustManagers = new TrustManager[]{new MergeTrustManager(ks, additionalTrustStore)};
            }

            KeyManager[] keyManagers = null;
            if (kmf != null) {
                keyManagers = kmf.getKeyManagers();
            }

            sslContext = CertificateHelper.newClientContext(keyManagers,
                    trustManagers);
            SSLEngine sslEngine = sslContext.createSSLEngine();
            SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            sslEngine.setSSLParameters(sslParams);
        } catch (Exception e) {
            throw new RuntimeException("Could not initialize SSL context.", e);
        }
    }

    private KeyStore loadKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
            try (FileInputStream is = new FileInputStream(
                    authority.aliasFile(KEY_STORE_FILE_EXTENSION))) {
                ks.load(is, authority.getPassword());
            }
            return ks;
        } catch (Exception e) {
            throw new RuntimeException("Could not load keys tore.", e);
        }
    }

    /**
     * Generates a new RSA key pair or gets it from the cache and sets it in the SSLEngine.
     * <p>
     * Derived from {@link "Zed Attack Proxy (ZAP)" https://gitlab.com/gitlab-org/security-products/zaproxy/-/tree/442fd33d65a9a3540b95e9ede372f3e044acdfc9}. ZAP is an HTTP/HTTPS proxy for
     * assessing web application security. Copyright 2011 mawoki@ymail.com
     * Licensed under the Apache License, Version 2.0.
     *
     * @param commonName              the common name to use in the server certificate
     * @param subjectAlternativeNames a List of the subject alternative names to use in the server
     *                                certificate, could be empty, but must not be null
     * @see org.parosproxy.paros.security.SslCertificateServiceImpl.
     * createCertForHost(String)
     * @see org.parosproxy.paros.network.SSLConnector.getTunnelSSLSocketFactory(
     * String)
     */
    public SSLEngine createCertForHost(final String commonName,
                                       final SubjectAlternativeNameHolder subjectAlternativeNames) {
        if (commonName == null) {
            throw new IllegalArgumentException(
                    "Error, 'commonName' is not allowed to be null!");
        }
        if (subjectAlternativeNames == null) {
            throw new IllegalArgumentException(
                    "Error, 'subjectAlternativeNames' is not allowed to be null!");
        }

        try {
            SSLContext ctx;
            if (serverSSLContexts == null) {
                ctx = createServerContext(commonName, subjectAlternativeNames);
            } else {
                ctx = serverSSLContexts.get(commonName, new Callable<SSLContext>() {
                    @Override
                    public SSLContext call() throws Exception {
                        return createServerContext(commonName,
                                subjectAlternativeNames);
                    }
                });
            }
            return ctx.createSSLEngine();
        } catch (Exception e) {
            throw new RuntimeException("Could not create certificate.", e);
        }
    }

    private SSLContext createServerContext(String commonName,
                                           SubjectAlternativeNameHolder subjectAlternativeNames) {

        MillisecondsDuration duration = new MillisecondsDuration();

        KeyStore ks = CertificateHelper.createServerCertificate(commonName,
                subjectAlternativeNames, authority, caCert, caPrivKey);
        KeyManager[] keyManagers = CertificateHelper.getKeyManagers(ks,
                authority);

        SSLContext result = CertificateHelper.newServerContext(keyManagers);

        LOG.info("Impersonated {} in {}ms", commonName, duration);
        return result;
    }

    public void initializeServerCertificates(String commonName,
                                             SubjectAlternativeNameHolder subjectAlternativeNames) {

        KeyStore ks = CertificateHelper.createServerCertificate(commonName,
                subjectAlternativeNames, authority, caCert, caPrivKey);

        try {
            PrivateKey key = (PrivateKey) ks.getKey(authority.getAlias(),
                    authority.getPassword());
            exportPem(authority.aliasFile("-" + commonName + "-key.pem"), key);

            Object[] certs = ks.getCertificateChain(authority.getAlias());
            exportPem(authority.aliasFile("-" + commonName + "-cert.pem"), certs);
        }
        catch (Exception e) {
            throw new RuntimeException("Could not export server certificate and key", e);
        }
    }

    private void exportPem(File exportFile, Object... certs)
            throws IOException {
        try (Writer sw = new FileWriter(exportFile)) {
            try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
                for (Object cert : certs) {
                    pw.writeObject(cert);
                    pw.flush();
                }
            }
        }
    }

}

class MillisecondsDuration {
    private final long mStartTime = System.currentTimeMillis();

    @Override
    public String toString() {
        return String.valueOf(System.currentTimeMillis() - mStartTime);
    }
}
