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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.PrivateKey;
import java.security.Signature;
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

    LogReader(KeyManager keyManager, File logFile) {
        this.keyManager = keyManager;
        this.logFile = logFile;
    }

    /**
     * Does a simple check of the accumulative hash in the file, and then checks that the signed accumulative hash is the same as we calculate
     */
    LogInfo checkLogFile() {
        final RandomAccessFile raf;
        try {
            raf = new RandomAccessFile(logFile, "r");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        try {
            final LogReaderContext context = new LogReaderContext();
            final LogFileHeaderInfo logFileHeaderInfo = readLogFileHeader(logFile, raf, context);
            final LogInfo logInfo = new LogInfo(logFileHeaderInfo);
            while (true) {
                final LogRecordInfo logRecordInfo = LogRecordInfo.read(raf, context);
                if (logRecordInfo.getRecordType() == RecordType.CLIENT_LOG_DATA || logRecordInfo.getRecordType() == RecordType.HEARTBEAT) {
                    //TODO Read the log records


                } else {
                    //Read the end of the file
                    checkRecordType(logRecordInfo, RecordType.ACCUMULATED_HASH);
                    logInfo.accumulatedHash = logRecordInfo.getBody();
                    final LogRecordInfo signatureInfo = LogRecordInfo.read(raf, context);
                    checkRecordType(signatureInfo, RecordType.LOG_FILE_SIGNATURE);
                    logInfo.signature = signatureInfo.getBody();
                    if (LogRecordInfo.read(raf, context) != null) {
                        throw new IllegalStateException("Unknown content at the end of the file");
                    }

                    if (!Arrays.equals(logInfo.accumulatedHash, logFileHeaderInfo.accumulativeDigest.getAccumulativeHash())) {
                        throw new IllegalStateException("The calculated accumulative hash was different from the accumulative hash record");
                    }

                    byte[] calculatedSignature;
                    try {
                        Signature signature = Signature.getInstance(keyManager.getSigningAlgorithmName());
                        signature.initSign(keyManager.getSigningPrivateKey());
                        signature.update(context.getAccumulativeDigest().getAccumulativeHash());
                        calculatedSignature = signature.sign();
                    } catch(Exception e) {
                        throw new IllegalStateException("Could not calculate signature", e);
                    }
                    if (!Arrays.equals(calculatedSignature, logInfo.signature)) {
                        throw new IllegalStateException("Signature differs");
                    }


                    return logInfo;
                }
            }

        } finally {
            IoUtils.safeClose(raf);
        }
    }

    private LogFileHeaderInfo readLogFileHeader(File logFile, RandomAccessFile raf, LogReaderContext context) {
        //Read hash algorithm
        LogRecordInfo.readHashAlgorithm(logFile, raf, context);


        //Secure random number
        LogRecordInfo.readSecureRandomBytes(raf, context, keyManager.getEncryptingPrivateKey());

        //Read the symmetric encryption keys
        final LogRecordInfo symmetricEncryptionKeyWithEncryptionPrivateKeyInfo = LogRecordInfo.read(raf, context);
        checkRecordType(symmetricEncryptionKeyWithEncryptionPrivateKeyInfo, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        final LogRecordInfo symmetricEncryptionKeyWithViewerPrivateKeyInfo = LogRecordInfo.read(raf, context);
        checkRecordType(symmetricEncryptionKeyWithViewerPrivateKeyInfo, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        final SecretKey secretKey;
        if (keyManager.getViewingPrivateKey() != null) {
            secretKey = decryptSymmetricEncryptionKey(symmetricEncryptionKeyWithViewerPrivateKeyInfo, keyManager.getViewingPrivateKey());
        } else if (keyManager.getEncryptingPrivateKey() != null){
            secretKey = decryptSymmetricEncryptionKey(symmetricEncryptionKeyWithEncryptionPrivateKeyInfo, keyManager.getEncryptingPrivateKey());
        } else {
            throw new IllegalStateException("No encrypting or viewing private key to decrypt the symmetric encryption key");
        }

        //Read the signing certificate
        final LogRecordInfo signingCertificateInfo = LogRecordInfo.read(raf, context);
        checkRecordType(signingCertificateInfo, RecordType.CERTIFICATE);
        final Certificate signingCertificate;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            signingCertificate = cf.generateCertificate(new ByteArrayInputStream(signingCertificateInfo.getBody()));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        //Read the header signature
        final LogRecordInfo headerSignatureInfo = LogRecordInfo.read(raf, context);
        checkRecordType(headerSignatureInfo, RecordType.HEADER_SIGNATURE);
        final byte[] headerSignature = headerSignatureInfo.getBody();

        //Read the last file name, hash and signature
        final LogRecordInfo lastFileInfo = LogRecordInfo.read(raf, context);
        String lastFileName;
        final byte[] lastFileHash;
        final byte[] lastFileSignature;
        if (lastFileInfo.getRecordType() == RecordType.LAST_FILE) {
            final byte[] nameBytes = new byte[bytesToInt(lastFileInfo.getBody(), 0)];
            System.arraycopy(lastFileInfo.getBody(), 4, nameBytes, 0, nameBytes.length);
            lastFileName = new String(nameBytes);
            lastFileHash = new byte[bytesToInt(lastFileInfo.getBody(), 4 + nameBytes.length)];
            System.arraycopy(lastFileInfo.getBody(), 8 + nameBytes.length, lastFileHash, 0, lastFileHash.length);
            if (new String(lastFileHash).equals("null")) {
                lastFileName = null;
            }
            lastFileSignature = new byte[bytesToInt(lastFileInfo.getBody(), 8 + nameBytes.length + lastFileHash.length)];
            System.arraycopy(lastFileInfo.getBody(), 12 + nameBytes.length + lastFileHash.length, lastFileSignature, 0, lastFileSignature.length);
        } else if (lastFileInfo.getRecordType() == RecordType.AUDITOR_NOTIFICATION) {
            lastFileName = null;
            lastFileHash = null;
            lastFileSignature = null;
        } else {
            throw new IllegalStateException("Expected to find last file information");
        }

        return new LogFileHeaderInfo(context.getAccumulativeDigest(), secretKey, signingCertificate, headerSignature, lastFileName, lastFileHash, lastFileSignature);
    }

    private SecretKey decryptSymmetricEncryptionKey(LogRecordInfo logRecordInfo, PrivateKey privateKey) {
        byte[] rawKey = decryptMessageUsingPrivateKey(logRecordInfo.getBody(), privateKey);
        if (rawKey == null) {
            throw new IllegalStateException("Could not decrypt symmetric encryption private key");
        }
        return new SecretKeySpec(rawKey, "AES");

    }

    private void checkRecordType(LogRecordInfo logRecordInfo, RecordType expectedType) {
        if (logRecordInfo.getRecordType() != expectedType) {
            throw new IllegalStateException("Expected recored type " + expectedType + "(" + expectedType.getByteValue() + "), but was" +
                    logRecordInfo.getRecordType() + "(" + logRecordInfo.getRecordType().getByteValue() + ")");
        }
    }


    private static byte[] decryptMessageUsingPrivateKey(byte[] message, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static int bytesToInt(byte[] bytes, int pos) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (bytes[i + pos] & 0x000000FF) << shift;
        }
        return value;
    }

    static class LogInfo {
        private LogFileHeaderInfo logFileHeaderInfo;
        private byte[] accumulatedHash;
        private byte[] signature;

        LogInfo(LogFileHeaderInfo logFileHeaderInfo){
            this.logFileHeaderInfo = logFileHeaderInfo;
        }

        byte[] getSignature() {
            return signature;
        }

        byte[] getAccumulatedHash() {
            return accumulatedHash;
        }
    }

    private static class LogFileHeaderInfo {
        final AccumulativeDigest accumulativeDigest;
        final SecretKey secretKey;
        final Certificate signingCertificate;
        final byte[] headerSignature;
        final String lastFileName;
        final byte[] lastFileHash;
        final byte[] lastSignature;

        LogFileHeaderInfo(final AccumulativeDigest accumulativeDigest, final SecretKey secretKey,
                final Certificate signingCertificate, final byte[] headerSignature, final String lastFileName, final byte[] lastFileHash,
                final byte[] lastSignature) {
            this.accumulativeDigest = accumulativeDigest;
            this.secretKey = secretKey;
            this.signingCertificate = signingCertificate;
            this.headerSignature = headerSignature;
            this.lastFileName = lastFileName;
            this.lastFileHash = lastFileHash;
            this.lastSignature = lastSignature;
        }
    }

    private static class LogRecordInfo {
        private final RecordType recordType;
        private final byte[] header;
        private final byte[] body;
        private final byte[] hash;

        private LogRecordInfo(RecordType recordType, byte[] header, byte[] body, byte[] hash) {
            this.recordType = recordType;
            this.header = header;
            this.body = body;
            this.hash = hash;
        }

        byte[] getHeader() {
            return header;
        }

        byte[] getBody() {
            return body;
        }

        byte[] getHash() {
            return hash;
        }

        static void readHashAlgorithm(File file, RandomAccessFile raf, LogReaderContext context) {
            try {
                final byte[] header = LogRecordInfo.readLogRecordHeader(raf);
                if (header == null) {
                    throw new IllegalStateException("Could not find hash algorithm header");
                }
                //int recordLength = getRecordLength(header);
                if (getRecordTypeByte(header) != RecordType.HASH_ALGORITHM.getByteValue()) {
                    throw new IllegalStateException("Could not find hash algorithm header");
                }
                final byte[] body = readRecordBody(raf, 0, 1);
                final HashAlgorithm hashAlgorithm = HashAlgorithm.fromByte(body[0]);
                final byte[] hash = readRecordHash(raf, hashAlgorithm);
                final AccumulativeDigest accumulativeDigest = AccumulativeDigest.createForReader(hashAlgorithm, file);
                final RecordType recordType = getRecordType(header);
                context.setAccumulativeDigest(accumulativeDigest);
                context.updateInfo(new LogRecordInfo(recordType, header, body, hash));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        static void readSecureRandomBytes(RandomAccessFile raf, LogReaderContext context, PrivateKey encryptingPrivateKey) {
            try {
                final byte[] header = LogRecordInfo.readLogRecordHeader(raf);
                if (header == null) {
                    throw new IllegalStateException("Could not find secure random header");
                }
                final int recordLength = getRecordLength(header);
                RecordType recordType = getRecordType(header);
                if (recordType != RecordType.SECRET_RANDOM_NUMBER) {
                    throw new IllegalStateException("Could not find secure random bytes header");
                }
                final byte[] body = readRecordBody(raf, 0, recordLength - context.getHashAlgorithm().getHashLength() - IoUtils.HEADER_LENGTH);
                final byte[] secureRandomBytes = decryptMessageUsingPrivateKey(body, encryptingPrivateKey);
                final byte[] hash = readRecordHash(raf, context.getHashAlgorithm());

                context.getAccumulativeDigest().setSecureRandomBytesForReading(secureRandomBytes);
                context.updateInfo(new LogRecordInfo(recordType, header, body, hash));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        static LogRecordInfo read(RandomAccessFile raf, LogReaderContext context) {
            final byte[] header = readLogRecordHeader(raf);
            if (header == null) {
                return null;
            }
            final int recordLength = getRecordLength(header);
            final byte[] body = readRecordBody(raf, 0, recordLength - context.getHashAlgorithm().getHashLength() - IoUtils.HEADER_LENGTH);
            final byte[] hash = readRecordHash(raf, context.getHashAlgorithm());
            RecordType recordType = getRecordType(header);

            LogRecordInfo logRecord = new LogRecordInfo(recordType, header, body, hash);
            context.updateInfo(logRecord);
            return logRecord;
        }


        static byte[] readRecordBody(RandomAccessFile raf, int offset, int length) {
            byte[] record = new byte[length];
            try {
                long pos = raf.getFilePointer();
                raf.seek(pos + offset);
                int lenRead = raf.read(record, 0, length);
                if (lenRead < length) {
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

        static byte[] readLogRecordHeader(RandomAccessFile raf) {
            final byte[] header;
            try {
                if (raf.getFilePointer() >= raf.length()) {
                    return null;
                }
                header = new byte[IoUtils.HEADER_LENGTH];
                int length = raf.read(header, 0, IoUtils.HEADER_LENGTH);

                //TODO better checks and exceptions
                if (length < IoUtils.HEADER_LENGTH) {
                    throw new RuntimeException("Could not read header");
                }
                return header;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private static byte[] readRecordHash(RandomAccessFile raf, HashAlgorithm hashAlgorithm) {
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

        private static int getRecordLength(byte[] header) {
            return bytesToInt(header, 22);
        }

        RecordType getRecordType() {
            return recordType;
        }

        private static RecordType getRecordType(byte[] header) {
            return RecordType.fromByte(getRecordTypeByte(header));
        }

        private static byte getRecordTypeByte(byte[] header) {
            return header[8];
        }
    }

    private static class LogReaderContext {
        private AccumulativeDigest accumulativeDigest;
        private LogRecordInfo lastInfo;

        void setAccumulativeDigest(AccumulativeDigest accumulativeDigest) {
            this.accumulativeDigest = accumulativeDigest;
        }

        void updateInfo(LogRecordInfo info) {
            accumulativeDigest.digestRecord(info.getRecordType(), info.getHeader(), info.getBody());
            lastInfo = info;
        }

        HashAlgorithm getHashAlgorithm() {
            return accumulativeDigest.getHashAlgorithm();
        }

        AccumulativeDigest getAccumulativeDigest() {
            return accumulativeDigest;
        }
    }

}
