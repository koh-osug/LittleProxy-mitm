package org.littleshoot.proxy.mitm;

/**
 * Doc
 *
 * @author <a href="mailto:kohme@gigsky.com">Karsten Ohme (kohme@gigsky.com)</a>
 */
public class BaseTest {

    static {
        java.security.Security.insertProviderAt(
                new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1
        );
        // otherwise the system on Ubuntu 20.04 with JDK 14 defines PKCS12 as defautl, which is not true for the cacerts keystore
        System.setProperty("javax.net.ssl.trustStoreType", "jks");
    }

}
