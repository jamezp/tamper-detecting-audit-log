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
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
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
    public SecureLoggerBuilder addRecoverAction(RecoverAction repairAction) {
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
    public void verifyLogFile(OutputStream outputStream, LogRecordBodyOutputter bodyOutputter, File file) throws KeyStoreInitializationException {
        verifyLogFileChain(outputStream, bodyOutputter, file, 0);
    }


    @Override
    public void verifyLogFileChain(final OutputStream outputStream, final LogRecordBodyOutputter bodyOutputter, final File file, final int count)
            throws KeyStoreInitializationException {
        LogFileNameUtil logFileNameUtil = new LogFileNameUtil(logFileDir);
        final File lastLogFile = logFileNameUtil.getPreviousLogFilename(null);
        final File inspectFile;
        if (file == null) {
            inspectFile = lastLogFile;
            if (inspectFile == null) {
                throw new IllegalStateException("Could not find any log files in " + logFileDir);
            }
        } else {
            inspectFile = file;
        }

        final boolean isLast = lastLogFile.getName().equals(inspectFile.getName());

        KeyManager keyManager = new KeyManager(encryptingStore.buildEncrypting(), signingStore.buildSigning(), viewingStore);
        LogReader reader = new LogReader(keyManager, inspectFile);
        RecoverableErrorContext recoverableContext = new RecoverableErrorContext(repairActions);
        TrustedLocation trustedLocation = null;
        if (isLast) {
            try {
                do {
                    trustedLocation = TrustedLocation.create(recoverableContext, keyManager, logFileDir, trustedLocationFile);
                } while (recoverableContext.isRecheck());
            }catch (RecoverableException e) {
                writeMessageToOutputStream(outputStream, "Error: " + e.getMessage() + "\n");
            }
        }

        //Always read the file in question
        LogInfo logInfo = null;
        try {
            logInfo = reader.verifyLogFile(outputStream, bodyOutputter);
        } catch (ValidationException e) {
            //Should not happen
            throw new IllegalStateException(e);
        }

        if (trustedLocation != null) {
            try {
                do {
                    trustedLocation.checkLastLogRecord(recoverableContext, logInfo);
                } while (recoverableContext.isRecheck());
            } catch (RecoverableException e) {
                writeMessageToOutputStream(outputStream, "Error: " + e.getMessage() + "\n");
            } catch (ValidationException e) {
                IoUtils.printStackTraceToOutputStream(e, outputStream);
            }
        }

        writeMessageToOutputStream(outputStream, "\n**** Finished inspection of " + logInfo.getLogFile().getName() + " ****\n");

        //Now check the chain if requested
        int current = count;
        while (current > 0 || current ==-1) {
            if (current > 0) {
                current--;
            }
            if (logInfo.getLastFileName() == null) {
                writeMessageToOutputStream(outputStream, "\n**** The last file name in " + logInfo.getLogFile().getName() + " is null. End of chain. ****\n");
                break;
            }

            File previousLogFile = new File(logFileDir, logInfo.getLastFileName());
            if (!previousLogFile.exists()) {
                writeMessageToOutputStream(outputStream, "Error: The last log file in " + logInfo.getLogFile().getName() + " was given as " + logInfo.getLastFileName() + ". That file does not exist. Searching for previous file to continue verification of chain before that file\n");
                previousLogFile = logFileNameUtil.getPreviousLogFilename(logInfo.getLogFile().getName());
                if (previousLogFile != null) {
                    writeMessageToOutputStream(outputStream, "\n*** Continuing verification with " + previousLogFile.getName() + " ***\n");
                } else {
                    writeMessageToOutputStream(outputStream, "Error: No earlier log files than " + logInfo.getLogFile().getName() + " could be found in " + logFileDir + "\n");
                    break;
                }
            } else {
                writeMessageToOutputStream(outputStream, "\n***  inspecting the previous log file " + previousLogFile.getName() + "***\n");
            }


            LogInfo lastInspected = logInfo;
            try {

                reader = new LogReader(keyManager, previousLogFile);
                logInfo = reader.verifyLogFile(outputStream, bodyOutputter);
            } catch (ValidationException e) {
                //Should not happen
                throw new IllegalStateException(e);
            }

            if (logInfo.getLastFileName() != null) {
                if (!Arrays.equals(lastInspected.getLastFileHash(), logInfo.getAccumulatedHash())){
                    writeMessageToOutputStream(outputStream, "Error: The last file hash recorded in " + logInfo.getLogFile().getName() + " is different from the accumulated hash in " + logInfo.getLogFile().getName() + "\n");
                }
                if (!Arrays.equals(lastInspected.getLastFileSignature(), logInfo.getSignature())) {
                    writeMessageToOutputStream(outputStream, "Error: The last file signature recorded in " + logInfo.getLogFile().getName() + " is different from the signature in " + logInfo.getLogFile().getName() + "\n");
                }
            } else {
                writeMessageToOutputStream(outputStream, "\n**** Finished inspection of " + logInfo.getLogFile().getName() + " ****\n");
            }
        }

    }

    private void writeMessageToOutputStream(OutputStream out, String message) {
        try {
            out.write(message.getBytes());
        } catch (IOException ie) {
            ie.printStackTrace();
        }

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