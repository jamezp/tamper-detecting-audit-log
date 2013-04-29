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
package org.jboss.audit.log.tamper.detecting;

import java.io.File;
import java.net.InetAddress;
import java.util.Date;
import java.util.concurrent.CountDownLatch;

import org.jboss.audit.log.AuditLogger;
import org.jboss.audit.log.simple.SimpleAuditLoggerBuilder;
import org.jboss.logmanager.Level;
import org.jboss.logmanager.handlers.SyslogHandler.SyslogType;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class SimpleAuditLoggerTestCase {

    File testLogDir;
    File trusted;

    @Before
    public void setupDirectories() {
        testLogDir = new File("target/test-logs");
        deleteDirectory(testLogDir);
        testLogDir.mkdirs();

        trusted = new File(testLogDir, "trusted");
        trusted.delete();
    }

    @Test
    public void testSimpleLogger() throws Exception {
        AuditLogger logger = SimpleAuditLoggerBuilder.createBuilder(testLogDir).buildLogger();
        try {
            logger.logMessage("One".getBytes());
            logger.logMessage("Two".getBytes());
        } finally {
            closeLog(logger);
        }
    }

    @Test
    public void testSimpleLoggerWithSyslog() throws Exception {
        AuditLogger logger =
                SimpleAuditLoggerBuilder.createBuilder(testLogDir)
                    .createSyslogAppenderBuilder()
                        .setServerAddress(InetAddress.getByName("192.168.1.25"))
                        .setAppName("Testing123")
                        .setLogLevel(Level.WARN)
                        .setTcp()
                        .setSyslogType(SyslogType.RFC3164) //This is the BSD/Mac version
                        .done()
                        .buildLogger();

        try {
            String msg = "Hello from Kabir " + new Date().toString() + "\n this is a new line";
            logger.logMessage(msg.getBytes());
        } finally {
            closeLog(logger);
        }

    }


    private void deleteDirectory(File file) {
        if (!file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            for (File child : file.listFiles()) {
                deleteDirectory(child);
            }
        } else {
            file.delete();
        }
    }

    private void closeLog(AuditLogger logger) throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(1);
        logger.closeLog(new AuditLogger.ClosedCallback() {

            @Override
            public void closed() {
                latch.countDown();
            }
        });
        latch.await();
    }
}
