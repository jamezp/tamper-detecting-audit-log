/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.audit.log.syslog4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;

import javax.net.ssl.SSLContext;

import junit.framework.Assert;
import org.jboss.audit.log.tamper.detecting.KeyStoreInitializationException;
import org.jboss.logmanager.Logger;
import org.jboss.logmanager.handlers.SyslogHandler;
import org.jboss.logmanager.handlers.SyslogHandler.SocketType;
import org.junit.Test;
import org.productivity.java.syslog4j.Syslog;
import org.productivity.java.syslog4j.SyslogIF;
import org.productivity.java.syslog4j.impl.net.tcp.TCPNetSyslogConfig;
import org.productivity.java.syslog4j.impl.net.tcp.ssl.SSLTCPNetSyslogConfig;

/**
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class Syslog4jTestCase {

    @Test
    public void testLocalSyslog() {
        Syslog.getInstance("udp").info("Test Local Syslog " + System.currentTimeMillis() + "\nnew line");
    }

    @Test
    public void testRemoteUdp() {
        SyslogIF syslog = Syslog.getInstance("udp");
        syslog.getConfig().setHost(getHostName());
        syslog.warn("Test UDP Remote Syslog " + System.currentTimeMillis() + "\n\tnew line");
    }

    @Test
    public void testRemoteTcp() {
        SyslogIF syslog = Syslog.getInstance("tcp");
        syslog.getConfig().setHost(getHostName());
        ((TCPNetSyslogConfig) syslog.getConfig()).setThreaded(false);
        syslog.warn("Test TCP Remote Syslog " + System.currentTimeMillis() + "\n\tnew line");
        syslog.flush();
        syslog.shutdown();
        System.out.print("Waiting for finish");
    }

    @Test
    public void testRemoteTls() throws Exception {
        System.setProperty("javax.net.debug", "all");

        SSLTCPNetSyslogConfig config = new SSLTCPNetSyslogConfig(getHostName(), 514);
        config.setTrustStore(new File(this.getClass().getResource("cacerts").toURI()).getAbsolutePath());
        config.setTrustStorePassword("changeit");
        config.setThreaded(false);
        SyslogIF syslog = Syslog.createInstance("sslTcp", config);
        syslog.warn("Test TCP Remote Syslog " + System.currentTimeMillis() + "\n\tnew line");
        syslog.flush();
        syslog.shutdown();
        System.out.print("Waiting for finish");
    }

    @Test
    public void testJbossTls() throws Exception {
        System.setProperty("javax.net.debug", "all");

        System.setProperty("javax.net.ssl.trustStore", new File(this.getClass().getResource("cacerts").toURI()).getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        final SyslogHandler handler = new SyslogHandler();
        handler.setSocketType(SocketType.SSL_TCP);
        handler.setHostname("localhost");
        final Logger logger = Logger.getLogger("org.wildfly.audit.log");
        logger.addHandler(handler);
        logger.warning("Test TCP Remote Syslog " + System.currentTimeMillis() + "\n\tnew line");
        handler.flush();
        handler.close();
        System.out.print("Waiting for finish");
    }

    @Test
    public void testRemoteTlsWithClientAuthentication() throws Exception {

        System.setProperty("javax.net.debug", "all");

        SSLTCPNetSyslogConfig config = new SSLTCPNetSyslogConfig(getHostName(), 514);
        config.setTrustStore(new File(this.getClass().getResource("cacerts").toURI()).getAbsolutePath());
        config.setTrustStorePassword("changeit");
        config.setKeyStore(new File(this.getClass().getResource("client/client.keystore").toURI()).getAbsolutePath());
        config.setKeyStorePassword("changeit");
        config.setThreaded(false);
        config.setWriteRetries(0);
        SyslogIF syslog = Syslog.createInstance("sslTcp", config);
        syslog.warn("Test TCP Remote Syslog with authentication " + System.currentTimeMillis() + "\n\tnew line");
        syslog.flush();
        syslog.shutdown();
        System.out.print("Waiting for finish");
    }

    @Test
    public void testLoadKeystore() throws Exception {
        File file = new File(this.getClass().getResource("client/client-cert.pem").toURI());
        Assert.assertTrue(file.exists());
        final InputStream in;
        try {
            in = new FileInputStream(file);
        } catch (IOException e) {
            throw new KeyStoreInitializationException(e);
        }
        try {
            java.security.cert.CertificateFactory cf = null;
            cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(in);
            PublicKey key = cert.getPublicKey();
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new KeyStoreInitializationException(e);
        }
    }

    protected String getHostName() {
        return System.getProperty("syslog.hostname", "localhost");
    }
}
