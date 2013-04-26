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

import org.jboss.audit.log.AuditLogger;
import org.jboss.audit.log.AuditLoggerBuilder;
import org.jboss.audit.log.LogFileNameUtil;
import org.jboss.audit.log.tamper.detecting.LogReader.LogInfo;
import org.jboss.audit.log.tamper.detecting.RecoverableErrorCondition.RecoverAction;
import org.jboss.audit.log.tamper.detecting.ServerKeyManager.EncryptingKeyPairInfo;
import org.jboss.audit.log.tamper.detecting.ServerKeyManager.SigningKeyPairInfo;

public class SecureAuditLoggerBuilder extends AuditLoggerBuilder<SecureAuditLoggerBuilder> {

    private EncryptingKeyPairInfo encryptingKeyPair;
    private SigningKeyPairInfo signingKeyPair;
    private ServerKeyManager.ViewingCertificateInfo viewingStore;
    private File trustedLocationFile;
    private Set<RecoverAction> repairActions = new HashSet<RecoverAction>();
    private boolean encryptLogMessages;

    private SecureAuditLoggerBuilder(File logFileDir) {
        super(logFileDir);
    }

    public static SecureAuditLoggerBuilder createBuilder(File logFileDir) {
        return new SecureAuditLoggerBuilder(logFileDir);
    }

    /**
     * Get the builder for the keystore information for the key pair used to encrypt/decrypt
     * the secure random number, and the encrypted log records
     *
     * @return the builder
     */
    public EncryptingKeyPairBuilder encryptingStoreBuilder() {
        return new EncryptingKeyPairBuilder();
    }

    /**
     * Get the builder for the keystore information for the key pair used to sign the
     * log record
     *
     * @return the builder
     */
    public SigningKeyPairBuilder signingStoreBuilder() {
        return new SigningKeyPairBuilder();
    }

    /**
     * Set the path for the certificate to view the log
     *
     * @param path the path of the viewing certificate
     * @return this builder
     */
    public SecureAuditLoggerBuilder setViewingCertificatePath(File path) throws KeyStoreInitializationException  {
        viewingStore = ServerKeyManager.ViewingCertificateInfo.create(path);
        return this;
    }

    /**
     * Set the trusted location maintaing the last log file, accumulated hash and sequence number
     *
     * @param file the trusted location path
     * @return this builder
     */
    public SecureAuditLoggerBuilder setTrustedLocation(File file) {
        trustedLocationFile = file;
        return this;
    }

    /**
     * Add a recover action to recover from a {@link RecoverableException} when calling {@link #buildLogger()}
     *
     * @return this builder
     */
    public SecureAuditLoggerBuilder addRecoverAction(RecoverAction repairAction) {
        repairActions.add(repairAction);
        return this;
    }

    /**
     * If called the logger will encrypt the user log messages
     *
     * @return this builder
     */
    public SecureAuditLoggerBuilder setEncryptLogMessages() {
        encryptLogMessages = true;
        return this;
    }


    public AuditLogger buildLogger() throws KeyStoreInitializationException, RecoverableException, ValidationException {
        RecoverableErrorContext recoverableContext = new RecoverableErrorContext(repairActions);
        ServerKeyManager keyManager = new ServerKeyManager(encryptingKeyPair, signingKeyPair, viewingStore);
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
        //TODO make configurable
        int heartbeat = 1;
        AuditLogger secureLogger = SecureAuditLogger.create(keyManager, logFileDir, trustedLocation, lastLogInfo, encryptLogMessages, heartbeat);
        return secureLogger;
    }

    public void verifyLogFile(OutputStream outputStream, LogRecordBodyOutputter bodyOutputter, File file) throws KeyStoreInitializationException {
        verifyLogFileChain(outputStream, bodyOutputter, file, 0);
    }


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

        ServerKeyManager keyManager = new ServerKeyManager(encryptingKeyPair, signingKeyPair, viewingStore);
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

    private class AbstractKeyPairBuilder<T extends AbstractKeyPairBuilder<T>> {
        File keyStorePath;
        String storePassword;
        String keyPassword;
        String keyName;

        public T setPath(File keyStorePath) {
            assert keyStorePath != null;
            this.keyStorePath = keyStorePath;
            return (T)this;
        }

        public T setStorePassword(String password) {
            this.storePassword = password;
            return (T)this;
        }

        public T setKeyPassword(String password) {
            this.keyPassword = password;
            return (T)this;
        }

        public T setKeyName(String name) {
            this.keyName = name;
            return (T)this;
        }

    }

    public class SigningKeyPairBuilder extends AbstractKeyPairBuilder<SigningKeyPairBuilder>{
        HashAlgorithm algorithm;

        public SigningKeyPairBuilder setHashAlgorithm(HashAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        SecureAuditLoggerBuilder done() throws KeyStoreInitializationException {
            try {
                signingKeyPair = ServerKeyManager.SigningKeyPairInfo.create(keyStorePath, storePassword, keyPassword, keyName, algorithm);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new KeyStoreInitializationException(e);
            }

            return SecureAuditLoggerBuilder.this;
        }
    }

    public class EncryptingKeyPairBuilder extends AbstractKeyPairBuilder<EncryptingKeyPairBuilder>{
        SecureAuditLoggerBuilder done() throws KeyStoreInitializationException {
            encryptingKeyPair = ServerKeyManager.EncryptingKeyPairInfo.create(keyStorePath, storePassword, keyPassword, keyName);
            return SecureAuditLoggerBuilder.this;
        }
    }
}