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
import java.util.concurrent.LinkedBlockingQueue;

class SecureLoggerBuilderImpl implements SecureLoggerBuilder {

    private KeyPairBuilderImpl encryptingStore;
    private KeyPairBuilderImpl signingStore;
    private KeyManager.ViewingCertificateInfo viewingStore;
    private File logFileDir;

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
    public SecureLogger buildLogger() throws KeyStoreInitializationException {
        KeyManager keyManager = new KeyManager(encryptingStore.buildEncrypting(), signingStore.buildSigning(), viewingStore);
        SecureLogger secureLogger = SecureLoggerImpl.create(keyManager, logFileDir, new LinkedBlockingQueue<LogRecord>());
        return secureLogger;
    }

    @Override
    public SecureLogReader buildReader() throws KeyStoreInitializationException {
        KeyManager keyManager = new KeyManager(encryptingStore.buildEncrypting(), signingStore.buildSigning(), viewingStore);
        SecureLogger secureLogger = SecureLoggerImpl.create(keyManager, logFileDir, new LinkedBlockingQueue<LogRecord>());
        return null;

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