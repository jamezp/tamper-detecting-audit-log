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


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class LogReader {
    private final KeyManager keyManager;
    private final File logFile;
    private final HashAlgorithm hashAlgorithm;

    LogReader(KeyManager keyManager, File logFile) {
        this.keyManager = keyManager;
        this.logFile = logFile;
        hashAlgorithm = readHashAlgorithm();
    }


    LogInfo verifyLogFile() {
        byte[] secureRandomNumber = readSecureRandomNumber();
        return checkLogFile(secureRandomNumber);
    }

    private LogInfo checkLogFile(byte[] secureRandomNumber) {
        try {
            final LogInfo logInfo = new LogInfo(logFile, createMessageDigest(hashAlgorithm));
            final RandomAccessFile raf = new RandomAccessFile(logFile, "r");
            try {
                while (true) {
                    String record = readRecord(raf, logInfo, secureRandomNumber);
                    if (record == null) {
                        return logInfo;
                    }
                    //TODO append this to the list?


                }
            } finally {
                IoUtils.safeClose(raf);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String readRecord(RandomAccessFile raf, LogInfo logInfo, byte[] secureRandomNumber) {
        final byte[] header = readLogRecordHeader(raf);
        if (header == null) {
            return null;
        }
        final int recordLength = getRecordLength(header);
        final int sequenceNumber = getSequenceNumber(header);
        final RecordType recordType = getRecordType(header);
        final StringBuilder sb = new StringBuilder();

        final byte[] message = readRecordBody(raf, 0, recordLength - hashAlgorithm.getHashLength() - IoUtils.HEADER_LENGTH);
        final byte[] hash = readRecordHash(raf);

        if (recordType == RecordType.ACCUMULATED_HASH) {
            logInfo.accumulatedHash = message;
        } else if (recordType == RecordType.LOG_FILE_SIGNATURE) {
            if (logInfo.accumulatedHash != null) {
                logInfo.signature = message;
                logInfo.complete = true;
            }
        } else {
            if (recordType == RecordType.CERTIFICATE) {
                logInfo.certificate = readX509Certificate(message);
            }else if (recordType == RecordType.SYMMETRIC_ENCRYPTION_KEY) {
                if (logInfo.secretKey == null && keyManager.getEncryptingPrivateKey() != null) {
                    byte[] rawKey = decryptMessageUsingPrivateKey(message, keyManager.getEncryptingPrivateKey());
                    if (rawKey != null && rawKey.length > 0) {
                        logInfo.secretKey = new SecretKeySpec(rawKey, "AES");
                    }
                }
            }

            //TODO allow for the user private key
            final byte[] plainMessage = getEncryptionType(header) == EncryptionType.SYMMETRIC ?
                    symmetricDecryptMessage(logInfo, message) : message;

            if (recordType == RecordType.LAST_FILE) {
                readLastLogFileRecord(logInfo, plainMessage);
            } else if (recordType == RecordType.CLIENT_LOG_DATA) {
                //TODO
            } else if (recordType == RecordType.AUDITOR_NOTIFICATION) {

            } else if (recordType == RecordType.HASH_ALGORITHM) {

            }

            if (logInfo.accumulatedHash == null) {
                byte[] fullRecord = new byte[header.length + message.length + hash.length];
                System.arraycopy(header, 0, fullRecord, 0, header.length);
                System.arraycopy(message, 0, fullRecord, header.length, message.length);
                System.arraycopy(hash, 0, fullRecord, header.length + message.length, hash.length);

                logInfo.accumulativeDigest.update(fullRecord);
                try{
                    MessageDigest clonedDigest =(MessageDigest) logInfo.accumulativeDigest.clone();
                    logInfo.calculatedAccumalativeHash = clonedDigest.digest();
                } catch(Exception e) {
                    throw new RuntimeException(e);
                }

                if (recordType == RecordType.HEADER_SIGNATURE) {
                    logInfo.accumulatedHashForLogHeader = logInfo.calculatedAccumalativeHash;
                    logInfo.headerSignature = message;
                }
            }

            if (secureRandomNumber != null) {
                final MessageDigest md = createMessageDigest(hashAlgorithm);
                md.update(header);
                md.update(message);
                md.update(secureRandomNumber);
                byte[] digest = md.digest();

                if (!Arrays.equals(hash, digest)) {
                    throw new RuntimeException("The secure hash of the record is wrong");
                }
            }
        }
        return "x";
    }



    private void readLastLogFileRecord(LogInfo logInfo, byte[] message) {
        //Last file name
        byte[] nameBytes = new byte[bytesToInt(message, 0)];
        System.arraycopy(message, 4, nameBytes, 0, nameBytes.length);
        String lastFileName = new String(nameBytes);
        if (lastFileName != null && !lastFileName.equals("null")) {
            logInfo.lastFilename = lastFileName;
        }

        //Last hash
        byte[] lastHash = new byte[bytesToInt(message, 4 + nameBytes.length)];
        System.arraycopy(message, 8 + nameBytes.length, lastHash, 0, lastHash.length);
        logInfo.lastAccumulatedHash = lastHash;
        if (new String(lastHash).equals("null")) {
            logInfo.lastFilename = null;
        }

        //Last signature
        byte[] lastSignature = new byte[bytesToInt(message, 8 + nameBytes.length + lastHash.length)];
        System.arraycopy(message, 12 + nameBytes.length + lastHash.length, lastSignature, 0, lastSignature.length);
        logInfo.lastSignature = lastSignature;
    }


    private byte[] readRecordHash(RandomAccessFile raf) {
        byte[] hash;
        int length;
        try {
            hash = new byte[hashAlgorithm.getHashLength()];
            length = raf.read(hash, 0, hashAlgorithm.getHashLength());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (length < hashAlgorithm.getHashLength()) {
            throw new IllegalStateException("Error reading hash");
        }
        return hash;
    }

    private HashAlgorithm readHashAlgorithm() {
        try {
            final RandomAccessFile raf = new RandomAccessFile(logFile, "r");
            try {
                while (true) {
                    byte[] header = readLogRecordHeader(raf);
                    if (header == null) {
                        throw new IllegalStateException("Could not find hash algorithm");
                    }
                    int recordLength = getRecordLength(header);
                    if (getRecordTypeByte(header) == RecordType.HASH_ALGORITHM.getByteValue()) {
                        byte[] message = readRecordBody(raf, 0, 1);
                        return HashAlgorithm.fromByte(message[0]);
                    }
                    moveFilePointer(raf, recordLength - IoUtils.HEADER_LENGTH);
                }
            } finally {
                IoUtils.safeClose(raf);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] readSecureRandomNumber() {
        try {
            final RandomAccessFile raf = new RandomAccessFile(logFile, "r");
            try {
                while (true) {
                    byte[] header = readLogRecordHeader(raf);
                    if (header == null) {
                        throw new IllegalStateException("Could not find secure random number");
                    }
                    int recordLength = getRecordLength(header);
                    if (getRecordTypeByte(header) == RecordType.SECRET_RANDOM_NUMBER.getByteValue()) {
                        byte[] message = readRecordBody(raf, 0, recordLength - keyManager.getHashAlgorithm().getHashLength() - IoUtils.HEADER_LENGTH);
                        return decryptMessageUsingPrivateKey(message, keyManager.getEncryptingPrivateKey());
                    }
                    moveFilePointer(raf, recordLength - IoUtils.HEADER_LENGTH);
                }
            } finally {
                IoUtils.safeClose(raf);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] decryptMessageUsingPrivateKey(byte[] message, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] symmetricDecryptMessage(LogInfo logInfo, byte[] message) {
        byte[] decipherText = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, logInfo.secretKey);
            decipherText = cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return decipherText;
    }

    private byte[] readLogRecordHeader(RandomAccessFile raf) {
        byte[] header = null;
        try {
            if (raf.getFilePointer() >= raf.length()) {
                return null;
            }
            header = new byte[IoUtils.HEADER_LENGTH];
            int length = raf.read(header, 0, IoUtils.HEADER_LENGTH);

            //TODO better checks and exceptions
            if (length < IoUtils.HEADER_LENGTH) {
                throw new RuntimeException();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return header;
    }

    private int getRecordLength(byte[] header) {
       return bytesToInt(header, 22);
    }

    private RecordType getRecordType(byte[] header) {
        return RecordType.fromByte(getRecordTypeByte(header));
    }

    private byte getRecordTypeByte(byte[] header) {
        return header[8];
    }

    private int getSequenceNumber(byte[] header) {
        return bytesToInt(header, 4);
    }

    private EncryptionType getEncryptionType(byte[] header) {
        return EncryptionType.fromByte(header[9]);
    }


    private void moveFilePointer(RandomAccessFile raf, int offset) {
        try {
            raf.seek(raf.getFilePointer() + offset);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] readRecordBody(RandomAccessFile raf, int offset, int len) {
        byte[] record = new byte[len];
        try {
            long pos = raf.getFilePointer();
            raf.seek(pos + offset);
            int lenRead = raf.read(record, 0, len);
            if (lenRead < len) {
                throw new RuntimeException("Could not read record body");
            }
            return record;
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException)e;
            }
            throw new RuntimeException(e);
        }
    }
    private int bytesToInt(byte[] bytes, int pos) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (bytes[i + pos] & 0x000000FF) << shift;
        }
        return value;
    }

    private MessageDigest createMessageDigest(HashAlgorithm hashAlgorithm) {
        try {
            return MessageDigest.getInstance(hashAlgorithm.toString());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private Certificate readX509Certificate(byte[] message) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificate(new ByteArrayInputStream(message));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    static class LogInfo {
        public byte[] lastSignature;
        private byte[] lastAccumulatedHash;
        private String lastFilename;

        private byte[] headerSignature;
        private byte[] accumulatedHashForLogHeader;
        private byte[] calculatedAccumalativeHash;
        private byte[] accumulatedHash;
        private byte[] signature;
        private Certificate certificate;
        private SecretKey secretKey;
        private boolean complete;
        private final MessageDigest accumulativeDigest;

        LogInfo(File logFile, MessageDigest accumulativeDigest){
            this.accumulativeDigest = accumulativeDigest;
            accumulativeDigest.update(logFile.getName().getBytes());
        }

        byte[] getSignature() {
            return signature;
        }

        byte[] getAccumulatedHash() {
            return accumulatedHash;
        }
    }
}
