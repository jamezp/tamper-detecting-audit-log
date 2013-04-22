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
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import org.jboss.audit.log.tamper.detecting.LogReader.LogInfo;
import org.jboss.audit.log.tamper.detecting.RecoverableErrorCondition.RecoverAction;

class SecureLoggerBuilderImpl implements SecureLoggerBuilder {

    private KeyPairBuilderImpl encryptingStore;
    private KeyPairBuilderImpl signingStore;
    private KeyManager.ViewingCertificateInfo viewingStore;
    private File logFileDir;
    private File trustedLocationFile;
    private Set<RecoverAction> repairActions = new HashSet<RecoverAction>();

    @Override
    public EncryptingKeyPairBuilder encryptingStoreBuilder() {
        return new KeyPairBuilderImpl(KeyStoreType.ENCRYPTING);
    }

    @Override
    public SigningKeyPairBuilder signingStoreBuilder() {
        return new KeyPairBuilderImpl(KeyStoreType.SIGNING);
    }

    @Override
    public SecureLoggerBuilder setViewingCertificatePath(File path) throws KeyStoreInitializationException  {
        viewingStore = KeyManager.ViewingCertificateInfo.create(path);
        return this;
    }

    @Override
    public SecureLoggerBuilder setLogFileRoot(File file) {
        logFileDir = file;
        return this;
    }

    @Override
    public SecureLoggerBuilder setTrustedLocation(File file) {
        trustedLocationFile = file;
        return this;
    }

    @Override
    public SecureLoggerBuilder addRepairAction(RecoverAction repairAction) {
        repairActions.add(repairAction);
        return this;
    }

    @Override
    public SecureLogger buildLogger() throws KeyStoreInitializationException, RecoverableException, ValidationException {
        RecoverableErrorContext recoverableContext = new RecoverableErrorContext(repairActions);
        KeyManager keyManager = new KeyManager(encryptingStore.buildEncrypting(), signingStore.buildSigning(), viewingStore);
        TrustedLocation trustedLocation;
        LogInfo lastLogInfo;
        do {
            trustedLocation = TrustedLocation.create(recoverableContext, keyManager, logFileDir, trustedLocationFile);
            lastLogInfo = null;
            if (trustedLocation.getCurrentInspectionLogFile() != null) {
                recoverableContext.resetRecheck();
                LogReader reader = new LogReader(keyManager, trustedLocation.getCurrentInspectionLogFile());
                lastLogInfo = reader.checkLogFile();
                trustedLocation.checkLastLogRecord(recoverableContext, lastLogInfo);
            }
        } while (recoverableContext.isRecheck());
        SecureLogger secureLogger = SecureLoggerImpl.create(keyManager, logFileDir, new LinkedBlockingQueue<LogWriterRecord>(), trustedLocation, lastLogInfo);
        return secureLogger;
    }


    @Override
    public List<File> listLogFiles() {
        LogFileNameUtil logFileNameUtil = new LogFileNameUtil(logFileDir);
        File file = logFileNameUtil.getPreviousLogFilename(null);
        List<File> files = new ArrayList<File>();
        if (file != null) {
            files.add(file);
            file = logFileNameUtil.getPreviousLogFilename(file.getName());
            while (file != null) {
                files.add(file);
                file = logFileNameUtil.getPreviousLogFilename(file.getName());
            }
        }
        return files;
    }

    @Override
    public void verifyLog(OutputStream outputStream, File file) throws KeyStoreInitializationException {
        if (file == null) {
            file = new LogFileNameUtil(logFileDir).getPreviousLogFilename(null);
            if (file == null) {
                throw new IllegalStateException("The log directory is empty");
            }
        }
        KeyManager keyManager = new KeyManager(encryptingStore.buildEncrypting(), signingStore.buildSigning(), viewingStore);
        LogReader reader = new LogReader(keyManager, logFileDir);
        try {
            reader.verifyLogFile(outputStream);
        } catch (ValidationException e) {
            //Should not happen
            throw new IllegalStateException(e);
        }
    }

    private class KeyPairBuilderImpl implements SigningKeyPairBuilder, EncryptingKeyPairBuilder {

        private final KeyStoreType type;
        private File keyStorePath;
        private String storePassword;
        private String keyPassword;
        private String keyName;
        private HashAlgorithm algorithm;

        public KeyPairBuilderImpl(KeyStoreType type) {
            this.type = type;
        }

        public KeyPairBuilderImpl setPath(File keyStorePath) {
            assert keyStorePath != null;
            this.keyStorePath = keyStorePath;
            return this;
        }

        public KeyPairBuilderImpl setStorePassword(String password) {
            this.storePassword = password;
            return this;
        }

        public KeyPairBuilderImpl setKeyPassword(String password) {
            this.keyPassword = password;
            return this;
        }

        public KeyPairBuilderImpl setKeyName(String name) {
            this.keyName = name;
            return this;
        }

        public KeyPairBuilderImpl setHashAlgorithm(HashAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public SecureLoggerBuilder done(){
            if (type == KeyStoreType.SIGNING) {
                signingStore = this;
            } else if (type == KeyStoreType.ENCRYPTING){
                encryptingStore = this;
            }
            return SecureLoggerBuilderImpl.this;
        }

        private KeyManager.SigningKeyPairInfo buildSigning() throws KeyStoreInitializationException {
            try {
                return KeyManager.SigningKeyPairInfo.create(keyStorePath, storePassword, keyPassword, keyName, algorithm);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException)e;
                }
                throw new KeyStoreInitializationException(e);
            }
        }

        private KeyManager.EncryptingKeyPairInfo buildEncrypting() throws KeyStoreInitializationException {
            try {
                return KeyManager.EncryptingKeyPairInfo.create(keyStorePath, storePassword, keyPassword, keyName);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException)e;
                }
                throw new KeyStoreInitializationException(e);
            }

        }
    }

    private enum KeyStoreType {
        SIGNING,
        ENCRYPTING;
    }
}