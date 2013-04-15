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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

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

    LogInfo verifyLogFile() {
        final RandomAccessFile raf;
        try {
            raf = new RandomAccessFile(logFile, "r");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        try {
            final LogFileHeaderInfo logFileHeaderInfo = readLogFileHeader(raf);
            final LogInfo logInfo = new LogInfo(logFileHeaderInfo);
            while (true) {
                final LogRecordInfo logRecordInfo = LogRecordInfo.read(raf, logFileHeaderInfo.hashAlgorithm);
                if (logRecordInfo.getRecordTypeByte() == RecordType.CLIENT_LOG_DATA.getByteValue()) {
                    //Read the log records


                } else {
                    //Read the end of the file
                    checkRecordType(logRecordInfo, RecordType.ACCUMULATED_HASH);
                    logInfo.accumulatedHash = logRecordInfo.getBody();
                    final LogRecordInfo signatureInfo = LogRecordInfo.read(raf, logFileHeaderInfo.hashAlgorithm);
                    checkRecordType(signatureInfo, RecordType.LOG_FILE_SIGNATURE);
                    logInfo.signature = signatureInfo.getBody();
                    if (LogRecordInfo.read(raf, logFileHeaderInfo.hashAlgorithm) != null) {
                        throw new IllegalStateException("Unknown content at the end of the file");
                    }

                    return logInfo;
                }
            }

        } finally {
            IoUtils.safeClose(raf);
        }
    }

    private LogFileHeaderInfo readLogFileHeader(RandomAccessFile raf) {
        //Read hash algorithm
        final HashAlgorithm hashAlgorithm = LogRecordInfo.readHashAlgorithm(raf);

        //Secure random number
        final LogRecordInfo secureRandomNumberInfo = LogRecordInfo.read(raf, hashAlgorithm);
        checkRecordType(secureRandomNumberInfo, RecordType.SECRET_RANDOM_NUMBER);
        final byte[] secureRandomNumber = decryptMessageUsingPrivateKey(secureRandomNumberInfo.getBody(), keyManager.getEncryptingPrivateKey());

        //Read the symmetric encryption keys
        final LogRecordInfo symmetricEncryptionKeyWithEncryptionPrivateKeyInfo = LogRecordInfo.read(raf, hashAlgorithm);
        checkRecordType(symmetricEncryptionKeyWithEncryptionPrivateKeyInfo, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        final LogRecordInfo symmetricEncryptionKeyWithViewerPrivateKeyInfo = LogRecordInfo.read(raf, hashAlgorithm);
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
        final LogRecordInfo signingCertificateInfo = LogRecordInfo.read(raf, hashAlgorithm);
        checkRecordType(signingCertificateInfo, RecordType.CERTIFICATE);
        final Certificate signingCertificate;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            signingCertificate = cf.generateCertificate(new ByteArrayInputStream(signingCertificateInfo.getBody()));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        //Read the header signature
        final LogRecordInfo headerSignatureInfo = LogRecordInfo.read(raf, hashAlgorithm);
        checkRecordType(headerSignatureInfo, RecordType.HEADER_SIGNATURE);
        final byte[] headerSignature = headerSignatureInfo.getBody();

        //Read the last file name, hash and signature
        final LogRecordInfo lastFileInfo = LogRecordInfo.read(raf, hashAlgorithm);
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

        return new LogFileHeaderInfo(hashAlgorithm, secureRandomNumber, secretKey, signingCertificate, headerSignature, lastFileName, lastFileHash, lastFileSignature);
    }

    private SecretKey decryptSymmetricEncryptionKey(LogRecordInfo logRecordInfo, PrivateKey privateKey) {
        byte[] rawKey = decryptMessageUsingPrivateKey(logRecordInfo.getBody(), privateKey);
        if (rawKey == null) {
            throw new IllegalStateException("Could not decrypt symmetric encryption private key");
        }
        return new SecretKeySpec(rawKey, "AES");

    }

    private void checkRecordType(LogRecordInfo logRecordInfo, RecordType expectedType) {
        if (logRecordInfo.getRecordTypeByte() != expectedType.getByteValue()) {
            throw new IllegalStateException("Expected recored type " + expectedType + "(" + expectedType.getByteValue() + "), but was" + logRecordInfo.getRecordTypeByte());
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

    private static byte[] readLogRecordHeader(RandomAccessFile raf) {
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

    private byte getRecordTypeByte(byte[] header) {
        return header[8];
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

//
//
//        public byte[] lastSignature;
//        private byte[] lastAccumulatedHash;
//        private String lastFilename;
//
//        private byte[] headerSignature;
//        private byte[] accumulatedHashForLogHeader;
//        private byte[] calculatedAccumalativeHash;
        private byte[] accumulatedHash;
        private byte[] signature;
//        private Certificate certificate;
//        private SecretKey secretKey;
//        private boolean complete;
//        private final MessageDigest accumulativeDigest;

        LogInfo(LogFileHeaderInfo logFileHeaderInfo){
            this.logFileHeaderInfo = logFileHeaderInfo;
        }

        byte[] getSignature() {
            return signature;
        }
//
//        byte[] getAccumulatedHash() {
//            return accumulatedHash;
//        }
    }

    private static class LogFileHeaderInfo {
        final HashAlgorithm hashAlgorithm;
        final byte[] secureRandomNumber;
        final SecretKey secretKey;
        final Certificate signingCertificate;
        final byte[] headerSignature;
        final String lastFileName;
        final byte[] lastFileHash;
        final byte[] lastSignature;

        LogFileHeaderInfo(final HashAlgorithm hashAlgorithm, final byte[] secureRandomNumber, final SecretKey secretKey,
                final Certificate signingCertificate, final byte[] headerSignature, final String lastFileName, final byte[] lastFileHash,
                final byte[] lastSignature) {
            this.hashAlgorithm = hashAlgorithm;
            this.secureRandomNumber = secureRandomNumber;
            this.secretKey = secretKey;
            this.signingCertificate = signingCertificate;
            this.headerSignature = headerSignature;
            this.lastFileName = lastFileName;
            this.lastFileHash = lastFileHash;
            this.lastSignature = lastSignature;
        }
    }

    private static class LogRecordInfo {
        private final byte[] header;
        private final byte[] body;
        private final byte[] hash;

        private LogRecordInfo(byte[] header, byte[] body, byte[] hash) {
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

        static HashAlgorithm readHashAlgorithm(RandomAccessFile raf) {
            try {
                byte[] header = LogRecordInfo.readLogRecordHeader(raf);
                if (header == null) {
                    throw new IllegalStateException("Could not find hash algorithm header");
                }
                //int recordLength = getRecordLength(header);
                if (getRecordTypeByte(header) != RecordType.HASH_ALGORITHM.getByteValue()) {
                    throw new IllegalStateException("Could not find hash algorithm header");
                }
                byte[] message = readRecordBody(raf, 0, 1);
                HashAlgorithm hashAlgorithm = HashAlgorithm.fromByte(message[0]);
                raf.seek(raf.getFilePointer() + hashAlgorithm.getHashLength());
                return hashAlgorithm;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        static LogRecordInfo read(RandomAccessFile raf, HashAlgorithm hashAlgorithm) {
            final byte[] header = readLogRecordHeader(raf);
            if (header == null) {
                return null;
            }
            final int recordLength = getRecordLength(header);
            final byte[] record = readRecordBody(raf, 0, recordLength - hashAlgorithm.getHashLength() - IoUtils.HEADER_LENGTH);
            final byte[] hash = readRecordHash(raf, hashAlgorithm);
            return new LogRecordInfo(header, record, hash);
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

        byte getRecordTypeByte() {
            return getRecordTypeByte(header);
        }

        RecordType getRecordType() {
            return getRecordType(header);
        }

        private static RecordType getRecordType(byte[] header) {
            return RecordType.fromByte(getRecordTypeByte(header));
        }

        private static byte getRecordTypeByte(byte[] header) {
            return header[8];
        }
    }
}
