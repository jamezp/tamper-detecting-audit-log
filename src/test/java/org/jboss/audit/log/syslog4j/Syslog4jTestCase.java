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

import org.junit.Test;
import org.productivity.java.syslog4j.Syslog;
import org.productivity.java.syslog4j.SyslogIF;
import org.productivity.java.syslog4j.impl.net.tcp.ssl.SSLTCPNetSyslogConfig;

/**
 *
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
        syslog.getConfig().setHost("192.168.1.25");
        syslog.warn("Test UDP Remote Syslog " + System.currentTimeMillis() + "\n\tnew line");
    }

    @Test
    public void testRemoteTcp() {
        SyslogIF syslog = Syslog.getInstance("tcp");
        syslog.getConfig().setHost("192.168.1.25");
        syslog.warn("Test TCP Remote Syslog " + System.currentTimeMillis() + "\n\tnew line");
        syslog.flush();
        syslog.shutdown();
        System.out.print("Waiting for finish");
    }

    @Test
    public void testRemoteTls() throws Exception {
        SSLTCPNetSyslogConfig config = new SSLTCPNetSyslogConfig("192.168.1.25", 10514);
        config.setTrustStore(new File(this.getClass().getResource("cacerts").toURI()).getAbsolutePath());
        config.setTrustStorePassword("changeit");
        SyslogIF syslog = Syslog.createInstance("sslTcp", config);
        syslog.warn("Test TCP Remote Syslog " + System.currentTimeMillis() + "\n\tnew line");
        syslog.flush();
        syslog.shutdown();
        System.out.print("Waiting for finish");
    }


}