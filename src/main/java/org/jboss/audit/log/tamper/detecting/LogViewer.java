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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;

import org.jboss.audit.log.LogFileNameUtil;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class LogViewer {

    private final PrivateKey viewingPrivateKey;
    private final File logFileDir;

    private LogViewer(PrivateKey viewingPrivateKey, File logFileDir) {
        this.viewingPrivateKey = viewingPrivateKey;
        this.logFileDir = logFileDir;
    }

    static LogViewer create(File viewingPk12Location, String viewingKeyStorePassword, String viewingPrivateKeyPassword, File logFileDir) throws KeyStoreInitializationException {
        try {
            final KeyStore viewingKeyStore = KeyStore.getInstance("PKCS12");
            final InputStream in = new BufferedInputStream(new FileInputStream(viewingPk12Location));
            try {
                viewingKeyStore.load(in, viewingPrivateKeyPassword.toCharArray());
                Enumeration<String> aliases = viewingKeyStore.aliases();
                if (!aliases.hasMoreElements()) {
                    throw new KeyStoreInitializationException("No entries found in the key store");
                }
                String alias = aliases.nextElement();
                PrivateKey privateKey = (PrivateKey)viewingKeyStore.getKey(alias, viewingPrivateKeyPassword.toCharArray());
                return new LogViewer(privateKey, logFileDir);
            } finally {
                IoUtils.safeClose(in);
            }
        } catch (Throwable t) {
            throw new KeyStoreInitializationException(t);
        }
    }

    void viewLogFile(OutputStream outputStream, LogRecordBodyOutputter bodyOutputter, File file) {
        if (file == null) {
            file = new LogFileNameUtil(logFileDir).getPreviousLogFilename(null);
        }
        LogReader logReader = new LogReader(null, file);
        logReader.viewLogFile(viewingPrivateKey, outputStream, bodyOutputter);
    }
}
