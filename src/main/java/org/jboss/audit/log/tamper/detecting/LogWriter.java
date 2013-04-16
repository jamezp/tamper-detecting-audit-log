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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

class LogWriter implements Runnable {
    private final KeyManager keyManager;
    private final BlockingQueue<LogWriterRecord> recordQueue;
    private final LogFileNameUtil logFileNameUtil;
    private final byte[] secureRandomBytes = new byte[IoUtils.SECURE_RANDOM_BYTES_LENGTH];
    private final TrustedLocation trustedLocation;
    private final AccumulativeDigest accumulativeDigest;
    private final AtomicBoolean doneThread = new AtomicBoolean(false);
    private final CountDownLatch doneLatch = new CountDownLatch(1);
    private volatile File logFile;
    private volatile int currentSequenceNumber;
    private volatile File currentLogFile;
    private volatile RandomAccessFile currentRandomAccessFile;
    private volatile SecretKey symmetricKeyInLog = null;
    private volatile int lastRecordLength;

    private LogWriter(KeyManager keyManager, File logFileDir, BlockingQueue<LogWriterRecord> recordQueue, TrustedLocation trustedLocation) {
        this.keyManager = keyManager;
        this.recordQueue = recordQueue;
        logFileNameUtil = new LogFileNameUtil(logFileDir);
        this.trustedLocation = trustedLocation;
        this.accumulativeDigest = AccumulativeDigest.createForWriter(keyManager.getHashAlgorithm(), secureRandomBytes);
    }

    static LogWriter create(KeyManager keyManager, File logFileDir, BlockingQueue<LogWriterRecord> recordQueue, TrustedLocation trustedLocation) {
        LogWriter writer = new LogWriter(keyManager, logFileDir, recordQueue, trustedLocation);
        writer.createNewLogFile();
        return writer;
    }

    private File createNewLogFile() {
        logFile = logFileNameUtil.generateNewLogFileName();
        System.out.println("-------> NEW FILE " + logFile);
        accumulativeDigest.resetForNewFile(logFile);
        currentSequenceNumber = 0;
        currentLogFile = logFile;
        try {
            currentRandomAccessFile = new RandomAccessFile(logFile, "rw");
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
            throw new RuntimeException(e);
        }

        logMessage(secureRandomBytes, RecordType.SECRET_RANDOM_NUMBER, EncryptionType.ASSYMETRIC);
        logMessage(rawKey, RecordType.SYMMETRIC_ENCRYPTION_KEY, EncryptionType.ASSYMETRIC);
        logMessage(rawKey, RecordType.SYMMETRIC_ENCRYPTION_KEY, EncryptionType.ASSYMETRIC, keyManager.getViewingPublicKey());
        logMessage(keyManager.getSigningPublicKeyCert(), RecordType.CERTIFICATE, EncryptionType.NONE);
        writeSignature(RecordType.HEADER_SIGNATURE);
        createLastLogFileRecord();
        trustedLocation.write(logFile, currentSequenceNumber, accumulativeDigest.getAccumulativeHash());

        return logFile;
    }

    private void createLastLogFileRecord() {
        if (trustedLocation.getPreviousLogFile() == null && trustedLocation.getCurrentInspectionLogFile() == null) {
            createLastFileRecord("This is the very first file in the log sequence", "null".getBytes(), "null".getBytes());
        } else if (trustedLocation.getPreviousLogFile() != null && trustedLocation.getCurrentInspectionLogFile() == null) {
            //We have a log, but no trusted location file
            logMessage("Trusted location is missing and reconstructed".getBytes(), RecordType.AUDITOR_NOTIFICATION, EncryptionType.NONE);
            //TODO more verification
        } else if (trustedLocation.getCurrentInspectionLogFile() != null){
            LogReader.LogInfo lastInfo = verifyLogFile(trustedLocation.getCurrentInspectionLogFile());
            createLastFileRecord(trustedLocation.getCurrentInspectionLogFile().getName(), trustedLocation.getAccumulatedMessageHash(), lastInfo.getSignature());
        }
    }

    private LogReader.LogInfo verifyLogFile(File logFile) {
        LogReader reader = new LogReader(keyManager, logFile);
        LogReader.LogInfo logInfo = reader.checkLogFile();

        trustedLocation.checkLastLogRecord(logInfo.getLastSequenceNumber(), logInfo.getAccumulatedHash());

        return logInfo;
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

    @Override
    public void run() {
        try {
            while (!doneThread.get()) {
                try {
                    LogWriterRecord logRecord = recordQueue.poll(1, TimeUnit.SECONDS);
                    if (logRecord != null) {
                        logMessage(logRecord.getData(), logRecord.getType(), EncryptionType.NONE);
                        logRecord.logged();
                    } else {
                        logMessage(new byte[0], RecordType.HEARTBEAT, EncryptionType.NONE);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } finally {
            IoUtils.safeClose(currentRandomAccessFile);
            doneLatch.countDown();
        }
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

    private void writeLogRecord(byte[] header, byte[] message, byte[] hash) {
        try {
            //System.out.println(header.length  + " : " + Arrays.toString(header));
            //System.out.println(message.length  + " : " + Arrays.toString(message));
            //System.out.println(hash.length  + " : " + Arrays.toString(hash));

            byte[] record = new byte[header.length + message.length + hash.length];
            System.arraycopy(header, 0, record, 0, header.length);
            System.arraycopy(message, 0, record, header.length, message.length);
            System.arraycopy(hash, 0, record, header.length + message.length, hash.length);

            currentRandomAccessFile.write(record);
            trustedLocation.write(logFile, currentSequenceNumber, accumulativeDigest.getAccumulativeHash());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void writeSignature(RecordType type) {
        try {
            Signature signature = Signature.getInstance(keyManager.getSigningAlgorithmName());
            signature.initSign(keyManager.getSigningPrivateKey());
            signature.update(accumulativeDigest.getAccumulativeHash());
            byte[] finalSignature = signature.sign();
            logMessage(finalSignature, type, EncryptionType.NONE);
        } catch (Exception e) {
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

    LogWriterRecord getCloseLogRecord(){
        LogWriterRecord.Callback callback = new LogWriterRecord.Callback() {
            @Override
            public void handled() {
                doneThread.set(true);
                writeSignature(RecordType.LOG_FILE_SIGNATURE);
                trustedLocation.write(logFile, currentSequenceNumber, accumulativeDigest.getAccumulativeHash());
            }
        };
        return new LogWriterRecord(null, RecordType.ACCUMULATED_HASH, callback) {
            byte[] getData() {
                return getAccumulativeHash();
            }
        };
    }

    public void awaitClose() {
        try {
            doneLatch.await();
        } catch (InterruptedException e) {
            //TODO handle this properly
            throw new RuntimeException(e);
        }
    }
}