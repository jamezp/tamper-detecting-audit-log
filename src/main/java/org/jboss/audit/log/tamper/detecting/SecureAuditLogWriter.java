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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jboss.audit.log.LogFileNameUtil;
import org.jboss.audit.log.LogWriter;
import org.jboss.audit.log.LogWriterRecord;
import org.jboss.audit.log.tamper.detecting.LogReader.LogInfo;
import org.jboss.audit.log.tamper.detecting.SecureAuditLogWriter.SecureAuditLogWriterRecord;

class SecureAuditLogWriter implements LogWriter<SecureAuditLogWriterRecord> {
    private final ServerKeyManager keyManager;
    private final LogFileNameUtil logFileNameUtil;
    private final byte[] secureRandomBytes = new byte[IoUtils.SECURE_RANDOM_BYTES_LENGTH];
    private final TrustedLocation trustedLocation;
    private final AccumulativeDigest accumulativeDigest;
    private final boolean encryptLogMessages;
    private volatile File logFile;
    private volatile int currentSequenceNumber;
    private volatile File currentLogFile;
    private volatile RandomAccessFile currentRandomAccessFile;
    private volatile SecretKey symmetricKeyInLog = null;
    private volatile int lastRecordLength;

    private SecureAuditLogWriter(ServerKeyManager keyManager, File logFileDir, TrustedLocation trustedLocation, boolean encryptLogMessages) {
        this.keyManager = keyManager;
        logFileNameUtil = new LogFileNameUtil(logFileDir);
        this.trustedLocation = trustedLocation;
        this.accumulativeDigest = AccumulativeDigest.createForWriter(keyManager.getHashAlgorithm(), secureRandomBytes);
        this.encryptLogMessages = encryptLogMessages;
    }

    private SecureAuditLogWriter(ServerKeyManager keyManager, File logFile, TrustedLocation trustedLocation, AccumulativeDigest accumulativeDigest, int sequenceNumber, int lastRecordLength, RandomAccessFile raf) {
        this.keyManager = keyManager;
        this.currentLogFile = logFile;
        this.trustedLocation = trustedLocation;
        this.accumulativeDigest = accumulativeDigest;
        this.currentSequenceNumber = currentSequenceNumber;
        this.lastRecordLength = lastRecordLength;
        this.currentRandomAccessFile = raf;
        logFileNameUtil = null;
        this.encryptLogMessages = false;
    }

    static SecureAuditLogWriter create(ServerKeyManager keyManager, File logFileDir, TrustedLocation trustedLocation, LogInfo lastLogInfo, boolean encryptLogMessages) {
        SecureAuditLogWriter writer = new SecureAuditLogWriter(keyManager, logFileDir, trustedLocation, encryptLogMessages);
        writer.createNewLogFile(lastLogInfo);
        return writer;
    }

    static FixingLogWriter createForFixing(ServerKeyManager keyManager, File logFile, TrustedLocation trustedLocation, AccumulativeDigest accumulativeDigest, int sequenceNumber, int lastRecordLength) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(logFile, "rw");
        try {
            raf.seek(raf.getFilePointer() + raf.length());
        } catch(IOException e) {
            IoUtils.safeClose(raf);
            throw e;
        } catch (Throwable t) {
            IoUtils.safeClose(raf);
            throw new RuntimeException(t);
        }
        SecureAuditLogWriter logWriter = new SecureAuditLogWriter(keyManager, logFile, trustedLocation, accumulativeDigest, sequenceNumber, lastRecordLength, raf);
        return logWriter.createFixingLogWriter();
    }


    private FixingLogWriter createFixingLogWriter() {
        return new FixingLogWriter() {
            public void writeMissingSignatureRecordAndCloseWriter() {
                try {
                    //TODO add this
                    //logMessage("The signature was missing. Adding it through an audit".getBytes(), RecordType.AUDITOR_NOTIFICATION, EncryptionType.NONE);
                    writeSignature(RecordType.LOG_FILE_SIGNATURE);
                } finally {
                    IoUtils.safeClose(currentRandomAccessFile);
                }
            }

            public void writeMissingAccumulatedHashAndSignatureRecordsAndCloseWriter() {
                try {
                    //TODO add this
                    //logMessage("The accumulated hash and signature were missing. Adding them through an audit".getBytes(), RecordType.AUDITOR_NOTIFICATION, EncryptionType.NONE);
                    logMessage(accumulativeDigest.getAccumulativeHash(), RecordType.ACCUMULATED_HASH, EncryptionType.NONE);
                    writeSignature(RecordType.LOG_FILE_SIGNATURE);
                } finally {
                    IoUtils.safeClose(currentRandomAccessFile);
                }
            }
        };
    }

    private File createNewLogFile(LogInfo lastLogInfo) {
        logFile = logFileNameUtil.generateNewLogFileName();
        accumulativeDigest.resetForNewFile(logFile);
        currentSequenceNumber = 0;
        currentLogFile = logFile;
        try {
            currentRandomAccessFile = new RandomAccessFile(logFile, "rwd");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }

        logMessage(new byte[] {keyManager.getHashAlgorithm().getByteValue()}, RecordType.HASH_ALGORITHM, EncryptionType.NONE);

        final KeyGenerator kgen;
        try {
            kgen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kgen.init(128);
        symmetricKeyInLog = kgen.generateKey();
        final byte[] rawKey = symmetricKeyInLog.getEncoded();
        try {
            final SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            random.nextBytes(secureRandomBytes);
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException)e;
            }
            throw new RuntimeException(e);
        }

        logMessage(secureRandomBytes, RecordType.SECRET_RANDOM_NUMBER, EncryptionType.ASSYMETRIC);
        logMessage(rawKey, RecordType.SYMMETRIC_ENCRYPTION_KEY, EncryptionType.ASSYMETRIC);
        logMessage(rawKey, RecordType.SYMMETRIC_ENCRYPTION_KEY, EncryptionType.ASSYMETRIC, keyManager.getViewingPublicKey());
        logMessage(keyManager.getSigningPublicKeyCert(), RecordType.CERTIFICATE, EncryptionType.NONE);
        writeSignature(RecordType.HEADER_SIGNATURE);
        createLastLogFileRecord(lastLogInfo);
        trustedLocation.write(logFile, currentSequenceNumber, accumulativeDigest.getAccumulativeHash());

        return logFile;
    }

    private void createLastLogFileRecord(LogInfo lastLogInfo) {
        if (trustedLocation.getPreviousLogFile() == null && trustedLocation.getCurrentInspectionLogFile() == null) {
            createLastFileRecord("This is the very first file in the log sequence", "null".getBytes(), "null".getBytes());
        } else if (trustedLocation.getPreviousLogFile() != null && trustedLocation.getCurrentInspectionLogFile() == null) {
            //We have a log, but no trusted location file
            logMessage("Trusted location is missing and reconstructed".getBytes(), RecordType.AUDITOR_NOTIFICATION, EncryptionType.NONE);
            //TODO more verification
        } else if (trustedLocation.getCurrentInspectionLogFile() != null){
            createLastFileRecord(trustedLocation.getCurrentInspectionLogFile().getName(), trustedLocation.getAccumulatedMessageHash(), lastLogInfo.getSignature());
        }
    }

    private void createLastFileRecord(String lastFilename, byte[] lastAccumulatedHash, byte[] lastSignature){
        byte[] nameBytes = lastFilename.getBytes();
        byte[] buffer = new byte[nameBytes.length + lastAccumulatedHash.length + lastSignature.length + 4*3 ];
        //Write name length and name
        System.arraycopy(HeaderUtil.intToByteArray(nameBytes.length), 0, buffer, 0, 4);
        System.arraycopy(nameBytes, 0, buffer, 4, nameBytes.length);

        //Write last accumulated hash length and hash
        System.arraycopy(HeaderUtil.intToByteArray(lastAccumulatedHash.length), 0, buffer, 4 + nameBytes.length , 4);
        System.arraycopy(lastAccumulatedHash, 0, buffer, 4 + nameBytes.length + 4, lastAccumulatedHash.length);

        //Write last signature length and signature
        System.arraycopy(HeaderUtil.intToByteArray(lastSignature.length), 0, buffer, 4 + nameBytes.length + 4 + lastAccumulatedHash.length , 4);   //
        System.arraycopy(lastSignature, 0, buffer, 4 + nameBytes.length + 4 + lastAccumulatedHash.length + 4, lastSignature.length);   //
        logMessage(buffer, RecordType.LAST_FILE, EncryptionType.NONE);
    }

    private void logMessage(byte[] message, RecordType type, EncryptionType encryptionType) {
       logMessage(message, type, encryptionType, keyManager.getEncryptingPublicKey());
    }

    private void logMessage(byte[] message, RecordType recordType, EncryptionType encryptionType, PublicKey encryptionPublicKey) {
        //System.out.println("=====> Writing " + recordType);
        if (encryptionType == EncryptionType.ASSYMETRIC) {
            ++currentSequenceNumber;
            byte[] encryptedMessage;
            try {
                Cipher cipher = Cipher.getInstance(encryptionPublicKey.getAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, encryptionPublicKey);
                encryptedMessage = cipher.doFinal(message);

            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException)e;
                }
                throw new RuntimeException(e);
            }
            final int recordLength = IoUtils.HEADER_LENGTH + encryptedMessage.length + keyManager.getHashAlgorithm().getHashLength();
            byte[] header = createHeader(recordType, encryptionType, lastRecordLength, recordLength);
            byte[] digest = accumulativeDigest.digestRecord(recordType, header, encryptedMessage);
            writeLogRecord(header, encryptedMessage, digest);
            lastRecordLength = recordLength;
        } else if (encryptionType == EncryptionType.SYMMETRIC) {
            final int recordLength;
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, symmetricKeyInLog);
                byte[] encryptedMessage = cipher.doFinal(message);
                recordLength = IoUtils.HEADER_LENGTH + encryptedMessage.length + keyManager.getHashAlgorithm().getHashLength();
                ++currentSequenceNumber;
                byte[] header = createHeader(recordType, encryptionType, lastRecordLength, recordLength);
                byte[] digest = accumulativeDigest.digestRecord(recordType, header, encryptedMessage);
                writeLogRecord(header, encryptedMessage, digest);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException)e;
                }
                throw new RuntimeException(e);
            }
            lastRecordLength = recordLength;
        } else if (encryptionType == EncryptionType.NONE) {
            final int recordLength = message.length + IoUtils.HEADER_LENGTH + keyManager.getHashAlgorithm().getHashLength();
            ++currentSequenceNumber;
            byte[] header = createHeader(recordType, encryptionType, lastRecordLength, recordLength);
            byte[] digest = accumulativeDigest.digestRecord(recordType, header, message);
            writeLogRecord(header, message, digest);
            lastRecordLength = recordLength;
        } else {
            throw new IllegalStateException("Unknown encryption type");
        }
    }

    private void writeLogRecord(byte[] header, byte[] message, byte[] digest) {
        try {
            //Write the log record
            byte[] record = new byte[header.length + message.length + digest.length];
            System.arraycopy(header, 0, record, 0, header.length);
            System.arraycopy(message, 0, record, header.length, message.length);
            System.arraycopy(digest, 0, record, header.length + message.length, digest.length);
            currentRandomAccessFile.write(record);

            //Write the trusted location
            trustedLocation.write(currentLogFile, currentSequenceNumber, accumulativeDigest.getAccumulativeHash());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void writeSignature(RecordType type) {
        logMessage(createSignature(keyManager, accumulativeDigest.getAccumulativeHash()), type, EncryptionType.NONE);
    }

    private static byte[] createSignature(ServerKeyManager keyManager, byte[] accumulativeHash) {
        try {
            Signature signature = Signature.getInstance(keyManager.getSigningAlgorithmName());
            signature.initSign(keyManager.getSigningPrivateKey());
            signature.update(accumulativeHash);
            return signature.sign();
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException)e;
            }
            throw new RuntimeException(e);
        }
    }

    private byte[] createHeader(RecordType type, EncryptionType encryptionType, int lastLength, int currentLength) {
        return HeaderUtil.createHeader(type, encryptionType, lastLength, currentLength, currentSequenceNumber);
    }


    String getLogFileName() {
        return currentLogFile.getName();
    }

    int getSequenceNumber() {
        return currentSequenceNumber;
    }

    byte[] getAccumulativeHash() {
        return accumulativeDigest.getAccumulativeHash();
    }

    interface FixingLogWriter {
        void writeMissingSignatureRecordAndCloseWriter();
        void writeMissingAccumulatedHashAndSignatureRecordsAndCloseWriter();
    }

    @Override
    public SecureAuditLogWriterRecord createLogRecord(byte[] message) {
        return new SecureAuditLogWriterRecord(message, RecordType.CLIENT_LOG_DATA);
    }

    @Override
    public void logRecord(SecureAuditLogWriterRecord record) {
        logMessage(record.getData(), record.getType(), encryptLogMessages ? EncryptionType.SYMMETRIC : EncryptionType.NONE);
    }

    @Override
    public void writeHeartbeat() {
        logMessage(new byte[0], RecordType.HEARTBEAT, EncryptionType.NONE);
    }

    @Override
    public void cycleLog() {
        //TOOD
    }

    @Override
    public void close() {
        logMessage(accumulativeDigest.getAccumulativeHash(), RecordType.ACCUMULATED_HASH, EncryptionType.NONE);
        writeSignature(RecordType.LOG_FILE_SIGNATURE);
    }

    static class SecureAuditLogWriterRecord implements LogWriterRecord {
        private final byte[] data;
        private final RecordType type;

        SecureAuditLogWriterRecord(byte[] data, RecordType type) {
            this.data = data;
            this.type = type;
        }

        byte[] getData() {
            return data;
        }

        RecordType getType() {
            return type;
        }
    }
}