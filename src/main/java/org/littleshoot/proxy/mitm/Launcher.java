package org.littleshoot.proxy.mitm;

import java.io.File;

import org.apache.log4j.xml.DOMConfigurator;
import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.HttpProxyServerBootstrap;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Launcher {

    private static final Logger log = LoggerFactory.getLogger(Launcher.class);

    public static void main(final String... args) {
        File log4jConfigurationFile = new File(
                "src/test/resources/log4j.xml");
        if (log4jConfigurationFile.exists()) {
            DOMConfigurator.configureAndWatch(
                    log4jConfigurationFile.getAbsolutePath(), 15);
        }
        try {
            final int port = 9090;

            log.info("About to start server on port: " + port);
            HttpProxyServerBootstrap bootstrap = DefaultHttpProxyServer
                    .bootstrapFromFile("./littleproxy.properties")
                    .withPort(port).withAllowLocalOnly(false);

            bootstrap.withManInTheMiddle(new CertificateSniffingMitmManager());

            log.info("About to start...");
            HttpProxyServer server = bootstrap.start();
            while (true) {
                Thread.yield();
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            System.exit(1);
        }
    }

}
