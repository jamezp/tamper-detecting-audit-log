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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

class LogWriter implements Runnable {
    private final KeyManager keyManager;
    private final BlockingQueue<LogRecord> recordQueue;
    private final File logFileDir;
    private final LogFileNameUtil logFileNameUtil;
    private final byte[] secureRandomBytes = new byte[20];
    private final TrustedLocation trustedLocation;
    private volatile byte[] accumulatedHash;
    private final MessageDigest accumulativeDigest;
    private final AtomicBoolean doneThread = new AtomicBoolean(false);
    private final CountDownLatch doneLatch = new CountDownLatch(1);
    private volatile int currentSequenceNumber;
    private volatile File currentLogFile;
    private volatile RandomAccessFile currentRandomAccessFile;
    private volatile SecretKey symmetricKeyInLog = null;
    private volatile int lastRecordLength;

    private LogWriter(KeyManager keyManager, File logFileDir, BlockingQueue<LogRecord> recordQueue, TrustedLocation trustedLocation) {
        this.keyManager = keyManager;
        this.logFileDir = logFileDir;
        this.recordQueue = recordQueue;
        logFileNameUtil = new LogFileNameUtil(logFileDir);
        this.accumulativeDigest = createMessageDigest();
        this.trustedLocation = trustedLocation;
    }

    static LogWriter create(KeyManager keyManager, File logFileDir, BlockingQueue<LogRecord> recordQueue, TrustedLocation trustedLocation) {
        LogWriter writer = new LogWriter(keyManager, logFileDir, recordQueue, trustedLocation);
        writer.createNewLogFile();
        return writer;
    }

    private MessageDigest createMessageDigest() {
        try {
            return MessageDigest.getInstance(keyManager.getHashAlgorithm().toString());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private File createNewLogFile() {
        final File file = logFileNameUtil.generateNewLogFileName();
        System.out.println("-------> NEW FILE " + file);
        accumulativeDigest.reset();
        accumulativeDigest.update(file.getName().getBytes());
        currentSequenceNumber = 0;
        currentLogFile = file;
        try {
            currentRandomAccessFile = new RandomAccessFile(file, "rw");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }

        final SecureRandom random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            random.nextBytes(secureRandomBytes);
        } catch (Exception e) {
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
        logMessage(secureRandomBytes, RecordType.SECRET_RANDOM_NUMBER, EncryptionType.ASSYMETRIC);
        logMessage(rawKey, RecordType.SYMMETRIC_ENCRYPTION_KEY, EncryptionType.ASSYMETRIC);
        logMessage(rawKey, RecordType.SYMMETRIC_ENCRYPTION_KEY, EncryptionType.ASSYMETRIC, keyManager.getViewingPublicKey());
        //TODO I think this is for user access control?
        /*
          Iterator idpkIt = UserIDPKMap.entrySet().iterator();
            while ( idpkIt.hasNext() ) {
                Map.Entry userIDPK = (Map.Entry) idpkIt.next();
                byte uID =  ((Byte) userIDPK.getKey() ).byteValue();
                PublicKey pk = (PublicKey) userIDPK.getValue();

                createSAWSRecord( rawKey,  SAWSConstant.SymmetricEncryptionKeyType,
                        (byte) uID,
                        SAWSConstant.AsymmetricEncryptionFlag,
                        pk) ;

            }
         */
        logMessage(keyManager.getSigningPublicKeyCert(), RecordType.CERTIFICATE, EncryptionType.NONE);
        writeSignature(RecordType.HEADER_SIGNATURE);
        createLastLogFileRecord();
        trustedLocation.write(this);

        return file;
    }

    private void createLastLogFileRecord() {
        if (trustedLocation.getPreviousLogFile() == null && trustedLocation.getCurrentInspectionLogFile() == null) {
            createLastFileRecord("This is the very first file in the log sequence", "null".getBytes(), "null".getBytes());
        } else if (trustedLocation.getPreviousLogFile() != null && trustedLocation.getCurrentInspectionLogFile() == null) {
            //We have a log, but no trusted location file
            logMessage("Trusted location is missing and reconstructed".getBytes(), RecordType.AUDITOR_NOTIFICATION, EncryptionType.NONE);
            //TODO more verification
        } else if (trustedLocation.getCurrentInspectionLogFile() != null){
            //TODO do we need to read the last signature from the previous log file?
            LogReader.LogInfo lastInfo = verifyLogFile(trustedLocation.getCurrentInspectionLogFile());
            createLastFileRecord(trustedLocation.getCurrentInspectionLogFile().getName(), trustedLocation.getAccumulatedMessageHash(), lastInfo.getSignature());//TODO the signature of the last file
        }
    }

    private LogReader.LogInfo verifyLogFile(File logFile) {
        LogReader reader = new LogReader(keyManager, logFile);
        return reader.verifyLogFile();
    }

    private void createLastFileRecord(String lastFilename, byte[] lastAccumulatedHash, byte[] lastSignature){
        byte[] nameBytes = lastFilename.getBytes();
        byte[] buffer = new byte[nameBytes.length + lastAccumulatedHash.length + lastSignature.length + 4*3 ];
        //Write name length and name
        System.arraycopy(intToByteArray(nameBytes.length), 0, buffer, 0, 4);
        System.arraycopy(nameBytes, 0, buffer, 4, nameBytes.length);

        //Write last accumulated hash length and hash
        System.arraycopy(intToByteArray(lastAccumulatedHash.length), 0, buffer, 4 + nameBytes.length , 4);
        System.arraycopy(lastAccumulatedHash, 0, buffer, 4 + nameBytes.length + 4, lastAccumulatedHash.length);

        //Write last signature length and signature
        System.arraycopy(intToByteArray(lastSignature.length), 0, buffer, 4 + nameBytes.length + 4 + lastAccumulatedHash.length , 4);   //
        System.arraycopy(lastSignature, 0, buffer, 4 + nameBytes.length + 4 + lastAccumulatedHash.length + 4, lastSignature.length);   //
        logMessage(buffer, RecordType.LAST_FILE, EncryptionType.NONE);
    }

    @Override
    public void run() {
        try {
            while (!doneThread.get()) {
                try {
                    LogRecord logRecord = recordQueue.take();
                    logMessage(logRecord.getData(), logRecord.getType(), EncryptionType.NONE);
                    trustedLocation.write(this);
                    logRecord.logged();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } finally {
            doneLatch.countDown();
        }
    }

    private void logMessage(byte[] message, RecordType type, EncryptionType encryptionType) {
       logMessage(message, type, encryptionType, keyManager.getEncryptingPublicKey());
    }

    private void logMessage(byte[] message, RecordType type, EncryptionType encryptionType, PublicKey encryptionPublicKey) {
        final byte record[];
        if (encryptionType == EncryptionType.ASSYMETRIC) {
            final int recordLength = IoUtils.HEADER_LENGTH + IoUtils.OUTPUTSIZE + keyManager.getHashAlgorithm().getHashLength();
            record = new byte[recordLength];
            ++currentSequenceNumber;
            appendHeader(record, type, encryptionType, lastRecordLength, recordLength);
            byte[] encryptedMessage;
            try {
                Cipher cipher = Cipher.getInstance(encryptionPublicKey.getAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, encryptionPublicKey);
                encryptedMessage = cipher.doFinal(message);
                System.arraycopy(encryptedMessage, 0, record, IoUtils.HEADER_LENGTH, IoUtils.OUTPUTSIZE);
                byte[] temp = new byte[IoUtils.HEADER_LENGTH + IoUtils.OUTPUTSIZE];
                System.arraycopy(record, 0, temp, 0, IoUtils.HEADER_LENGTH + IoUtils.OUTPUTSIZE);
                byte[] digest = digestBytes(temp);
                System.arraycopy(digest, 0, record, IoUtils.HEADER_LENGTH + IoUtils.OUTPUTSIZE, keyManager.getHashAlgorithm().getHashLength());

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            lastRecordLength = recordLength;
        } else if (encryptionType == EncryptionType.SYMMETRIC) {
            final int recordLength;
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, symmetricKeyInLog);
                byte[] encrypted = cipher.doFinal(message);
                recordLength = IoUtils.HEADER_LENGTH + encrypted.length + keyManager.getHashAlgorithm().getHashLength();
                record = new byte[recordLength];
                ++currentSequenceNumber;
                appendHeader(record, type, encryptionType, lastRecordLength, recordLength);
                System.arraycopy(encrypted, 0, record, IoUtils.HEADER_LENGTH, encrypted.length);
                byte[] temp = new byte[IoUtils.HEADER_LENGTH + encrypted.length];
                System.arraycopy(record, 0, temp, 0, IoUtils.HEADER_LENGTH + encrypted.length);
                byte[] digest = digestBytes(temp);
                System.arraycopy(digest, 0, record, IoUtils.HEADER_LENGTH + encrypted.length, keyManager.getHashAlgorithm().getHashLength());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            lastRecordLength = recordLength;
        } else if (encryptionType == EncryptionType.NONE) {
            final int recordLength = message.length + IoUtils.HEADER_LENGTH + keyManager.getHashAlgorithm().getHashLength();
            record = new byte[recordLength];
            ++currentSequenceNumber;
            appendHeader(record, type, encryptionType, lastRecordLength, recordLength);
            System.arraycopy(message, 0, record, IoUtils.HEADER_LENGTH, message.length);
            byte[] temp = new byte[IoUtils.HEADER_LENGTH + message.length];
            System.arraycopy(record, 0, temp, 0, temp.length);
            byte[] digest = digestBytes(temp);
            System.arraycopy(digest, 0, record, IoUtils.HEADER_LENGTH + message.length, keyManager.getHashAlgorithm().getHashLength());
            lastRecordLength = recordLength;
        } else {
            throw new IllegalStateException("Unknown encryption type");
        }


        if (type != RecordType.ACCUMULATED_HASH && type != RecordType.LOG_FILE_SIGNATURE) {
            accumulativeDigest.update(record);
            try {
                MessageDigest accumulativeDigestCopy = (MessageDigest)accumulativeDigest.clone();
                accumulatedHash = accumulativeDigestCopy.digest();
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }
        try {
            System.out.println("---> Writing " + type + " " + currentSequenceNumber);
            System.out.println(Arrays.toString(record));
            currentRandomAccessFile.write(record);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void writeSignature(RecordType type) {
        try {
            Signature signature = Signature.getInstance(keyManager.getSigningAlgorithmName());
            signature.initSign(keyManager.getSigningPrivateKey());
            signature.update(accumulatedHash);
            byte[] finalSignature = signature.sign();
            logMessage(finalSignature, type, EncryptionType.NONE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] digestBytes(byte[] bytes) {
        final MessageDigest md = createMessageDigest();
        md.reset();
        md.update(bytes);
        md.update(secureRandomBytes);
        return md.digest();

    }

    private byte[] appendHeader(byte[] header, RecordType type, EncryptionType encryptionType, int lastLength, int currentLength) {
        header[0] = (byte)0xf0;
        header[1] = (byte)0xf0;
        header[2] = (byte)0xf0;
        header[3] = (byte)0xf0;
        appendInt4Bytes(header, 4, currentSequenceNumber);
        header[8] = type.getByteValue();
        header[9] = encryptionType.getByteValue();
        appendLong8Bytes(header, 10, System.currentTimeMillis());
        appendInt4Bytes(header, 18, lastLength);
        appendInt4Bytes(header, 22, currentLength);

        return header;
    }

    private void appendInt4Bytes(byte[] bytes, int pos, int value) {
        for (int i = 0; i < 4; i++) {
            int offset = (4 - 1 - i) * 8;
            bytes[i + pos] = (byte) ((value >>> offset) & 0xFF);
        }
    }

    private byte[] intToByteArray(int value) {
        byte[] bytes = new byte[4];
        appendInt4Bytes(bytes, 0, value);
        return bytes;
    }

    private void appendLong8Bytes(byte[] bytes, int pos, long value) {
        for (int i = 0; i < 8; i++) {
            int offset = (8 - 1 - i) * 8;
            bytes[i + pos] = (byte) ((value >>> offset) & 0xFF);
        }
    }

    String getLogFileName() {
        return currentLogFile.getName();
    }

    int getSequenceNumber() {
        return currentSequenceNumber;
    }

    byte[] getAccumulativeHash() {
        return accumulatedHash;
    }

    LogRecord getCloseLogRecord(){
        LogRecord.Callback callback = new LogRecord.Callback() {
            @Override
            public void handled() {
                doneThread.set(true);
                writeSignature(RecordType.LOG_FILE_SIGNATURE);
                trustedLocation.write(LogWriter.this);
            }
        };
        return new LogRecord(null, RecordType.ACCUMULATED_HASH, callback) {
            byte[] getData() {
                return accumulatedHash;
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