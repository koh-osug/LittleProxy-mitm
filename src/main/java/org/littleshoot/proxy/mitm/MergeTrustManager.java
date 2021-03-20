package org.littleshoot.proxy.mitm;

import lombok.experimental.Delegate;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class MergeTrustManager implements X509TrustManager {

    @Delegate(types = X509TrustManager.class)
    private final X509TrustManager compositeX509TrustManager;

    private static class CompositeX509TrustManager implements X509TrustManager {

        private final List<X509TrustManager> children;

        public CompositeX509TrustManager(X509TrustManager... children) {
            this.children = Arrays.asList(children);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            CertificateException lastError = null;
            for (X509TrustManager trustManager : children) {
                try {
                    trustManager.checkClientTrusted(chain, authType);
                    return;
                } catch (CertificateException ex) {
                    lastError = ex;
                }
            }

            if (lastError != null) {
                throw lastError;
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            CertificateException lastError = null;
            for (X509TrustManager trustManager : children) {
                try {
                    trustManager.checkServerTrusted(chain, authType);
                    return;
                } catch (CertificateException ex) {
                    lastError = ex;
                }
            }

            if (lastError != null) {
                throw lastError;
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return merge(X509TrustManager::getAcceptedIssuers);
        }

        private X509Certificate[] merge(Function<X509TrustManager, X509Certificate[]> map) {
            return children.stream().flatMap(x -> Arrays.stream(map.apply(x)))
                    .toArray(X509Certificate[]::new);
        }
    }

    public MergeTrustManager(KeyStore... trustStores)
            throws NoSuchAlgorithmException, KeyStoreException {
        if (trustStores == null) {
            throw new IllegalArgumentException("Missing trust store");
        }
        final List<X509TrustManager> trustManagers = new ArrayList<>();
        trustManagers.add(defaultTrustManager(null));
        Arrays.stream(trustStores).filter(Objects::nonNull).forEach(
                t -> trustManagers.add(defaultTrustManager(t))
        );
        this.compositeX509TrustManager = new CompositeX509TrustManager(
               trustManagers.toArray(trustManagers.toArray(new X509TrustManager[0])));
    }

    private X509TrustManager defaultTrustManager(KeyStore trustStore) {
        String tma = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = null;
        try {
            tmf = TrustManagerFactory.getInstance(tma);
            tmf.init(trustStore);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException("Could not init default trust manager", e);
        }
        TrustManager[] trustManagers = tmf.getTrustManagers();
        for (TrustManager each : trustManagers) {
            if (each instanceof X509TrustManager) {
                return (X509TrustManager) each;
            }
        }
        throw new IllegalStateException("Missed X509TrustManager in "
                + Arrays.toString(trustManagers));
    }

}
