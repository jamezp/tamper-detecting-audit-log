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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
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
        return readLogFile(new SimpleCheckLogFileRecordListener());
    }

    LogInfo outputLogFile() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        LogInfo logInfo = readLogFile(new OutputtingLogFileRecordListener(out));
        System.out.println(new String(out.toByteArray()));
        return logInfo;
    }


    LogInfo readLogFile(LogReaderRecordListener listener) {
        final RandomAccessFile raf;
        try {
            raf = new RandomAccessFile(logFile, "r");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        try {
            final LogFileHeaderInfo logFileHeaderInfo = readLogFileHeader(logFile, raf, listener);
            final LogInfo logInfo = new LogInfo(logFile, logFileHeaderInfo);
            while (true) {
                final LogReaderRecord logRecordInfo = LogReaderRecord.read(raf, logFileHeaderInfo.accumulativeDigest);
                if (logRecordInfo == null) {
                    return logInfo;
                }

                logInfo.updateLastRecord(logRecordInfo);
                listener.recordAdded(logRecordInfo);

                if (logRecordInfo.getRecordType() == RecordType.CLIENT_LOG_DATA || logRecordInfo.getRecordType() == RecordType.HEARTBEAT) {
                    //TODO Read the log records

                } else {
                    //Read the end of the file
                    checkRecordType(logRecordInfo, RecordType.ACCUMULATED_HASH);
                    logInfo.accumulatedHash = logRecordInfo.getBody();

                    final LogReaderRecord signatureInfo = LogReaderRecord.read(raf, logFileHeaderInfo.accumulativeDigest);
                    if (signatureInfo != null) {
                        logInfo.updateLastRecord(signatureInfo);
                        listener.recordAdded(signatureInfo);
                        checkRecordType(signatureInfo, RecordType.LOG_FILE_SIGNATURE);
                        logInfo.signature = signatureInfo.getBody();
                        if (LogReaderRecord.read(raf, logFileHeaderInfo.accumulativeDigest) != null) {
                            //TODO throw or log
                            throw new IllegalStateException("Unknown content at the end of the file");
                        }

                        if (!Arrays.equals(logInfo.accumulatedHash, logFileHeaderInfo.accumulativeDigest.getAccumulativeHash())) {
                            //TODO throw or log
                            throw new IllegalStateException("The calculated accumulative hash was different from the accumulative hash record");
                        }

                        byte[] calculatedSignature;
                        try {
                            Signature signature = Signature.getInstance(keyManager.getSigningAlgorithmName());
                            signature.initSign(keyManager.getSigningPrivateKey());
                            signature.update(logFileHeaderInfo.accumulativeDigest.getAccumulativeHash());
                            calculatedSignature = signature.sign();
                        } catch(Exception e) {
                            //TODO throw or log
                            throw new IllegalStateException("Could not calculate signature", e);
                        }
                        if (!Arrays.equals(calculatedSignature, logInfo.signature)) {
                            //TODO throw or log
                            throw new IllegalStateException("Signature differs");
                        }
                    }

                    return logInfo;
                }
            }

        } finally {
            IoUtils.safeClose(raf);
        }
    }

    private LogFileHeaderInfo readLogFileHeader(File logFile, RandomAccessFile raf, LogReaderRecordListener listener) {
        //Read hash algorithm
        LogReaderRecord hashAlgorithmRecord = LogReaderRecord.readHashAlgorithm(logFile, raf);
        final HashAlgorithm hashAlgorithm = HashAlgorithm.fromByte(hashAlgorithmRecord.getBody()[0]);
        final AccumulativeDigest accumulativeDigest = AccumulativeDigest.createForReader(hashAlgorithm, logFile);
        listener.setAccumulativeDigest(accumulativeDigest);
        listener.recordAdded(hashAlgorithmRecord);

        //Secure random number
        LogReaderRecord secureRandomBytesRecord = LogReaderRecord.read(raf, accumulativeDigest);
        checkRecordType(secureRandomBytesRecord, RecordType.SECRET_RANDOM_NUMBER);
        final byte[] secureRandomBytes = LogReader.decryptMessageUsingPrivateKey(secureRandomBytesRecord.getBody(), keyManager.getEncryptingPrivateKey());
        accumulativeDigest.setSecureRandomBytesForReading(secureRandomBytes);
        listener.recordAdded(secureRandomBytesRecord);

        //Read the symmetric encryption keys
        final LogReaderRecord symmetricEncryptionKeyWithEncryptionPrivateKeyInfo = LogReaderRecord.read(raf, accumulativeDigest);
        checkRecordType(symmetricEncryptionKeyWithEncryptionPrivateKeyInfo, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        listener.recordAdded(symmetricEncryptionKeyWithEncryptionPrivateKeyInfo);

        final LogReaderRecord symmetricEncryptionKeyWithViewerPrivateKeyInfo = LogReaderRecord.read(raf, accumulativeDigest);
        checkRecordType(symmetricEncryptionKeyWithViewerPrivateKeyInfo, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        listener.recordAdded(symmetricEncryptionKeyWithViewerPrivateKeyInfo);

        final SecretKey secretKey;
        if (keyManager.getViewingPrivateKey() != null) {
            secretKey = decryptSymmetricEncryptionKey(symmetricEncryptionKeyWithViewerPrivateKeyInfo, keyManager.getViewingPrivateKey());
        } else if (keyManager.getEncryptingPrivateKey() != null){
            secretKey = decryptSymmetricEncryptionKey(symmetricEncryptionKeyWithEncryptionPrivateKeyInfo, keyManager.getEncryptingPrivateKey());
        } else {
            throw new IllegalStateException("No encrypting or viewing private key to decrypt the symmetric encryption key");
        }

        //Read the signing certificate
        final LogReaderRecord signingCertificateInfo = LogReaderRecord.read(raf, accumulativeDigest);
        checkRecordType(signingCertificateInfo, RecordType.CERTIFICATE);
        listener.recordAdded(signingCertificateInfo);
        final Certificate signingCertificate;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            signingCertificate = cf.generateCertificate(new ByteArrayInputStream(signingCertificateInfo.getBody()));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        //Read the header signature
        final LogReaderRecord headerSignatureInfo = LogReaderRecord.read(raf, accumulativeDigest);
        checkRecordType(headerSignatureInfo, RecordType.HEADER_SIGNATURE);
        listener.recordAdded(headerSignatureInfo);
        final byte[] headerSignature = headerSignatureInfo.getBody();

        //Read the last file name, hash and signature
        final LogReaderRecord lastFileInfo = LogReaderRecord.read(raf, accumulativeDigest);
        listener.recordAdded(lastFileInfo);
        String lastFileName;
        final byte[] lastFileHash;
        final byte[] lastFileSignature;
        if (lastFileInfo.getRecordType() == RecordType.LAST_FILE) {
            final byte[] nameBytes = new byte[HeaderUtil.bytesToInt(lastFileInfo.getBody(), 0)];
            System.arraycopy(lastFileInfo.getBody(), 4, nameBytes, 0, nameBytes.length);
            lastFileName = new String(nameBytes);
            lastFileHash = new byte[HeaderUtil.bytesToInt(lastFileInfo.getBody(), 4 + nameBytes.length)];
            System.arraycopy(lastFileInfo.getBody(), 8 + nameBytes.length, lastFileHash, 0, lastFileHash.length);
            if (new String(lastFileHash).equals("null")) {
                lastFileName = null;
            }
            lastFileSignature = new byte[HeaderUtil.bytesToInt(lastFileInfo.getBody(), 8 + nameBytes.length + lastFileHash.length)];
            System.arraycopy(lastFileInfo.getBody(), 12 + nameBytes.length + lastFileHash.length, lastFileSignature, 0, lastFileSignature.length);
        } else if (lastFileInfo.getRecordType() == RecordType.AUDITOR_NOTIFICATION) {
            lastFileName = null;
            lastFileHash = null;
            lastFileSignature = null;
        } else {
            throw new IllegalStateException("Expected to find last file information");
        }

        return new LogFileHeaderInfo(accumulativeDigest, secretKey, signingCertificate, headerSignature, lastFileName, lastFileHash, lastFileSignature);
    }

    private SecretKey decryptSymmetricEncryptionKey(LogReaderRecord logRecordInfo, PrivateKey privateKey) {
        byte[] rawKey = decryptMessageUsingPrivateKey(logRecordInfo.getBody(), privateKey);
        if (rawKey == null) {
            throw new IllegalStateException("Could not decrypt symmetric encryption private key");
        }
        return new SecretKeySpec(rawKey, "AES");

    }

    private void checkRecordType(LogReaderRecord logRecordInfo, RecordType expectedType) {
        if (logRecordInfo.getRecordType() != expectedType) {
            throw new IllegalStateException("Expected recored type " + expectedType + "(" + expectedType.getByteValue() + "), but was" +
                    logRecordInfo.getRecordType() + "(" + logRecordInfo.getRecordType().getByteValue() + ")");
        }
    }


    static byte[] decryptMessageUsingPrivateKey(byte[] message, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static class LogInfo {
        private final File logFile;
        private final LogFileHeaderInfo logFileHeaderInfo;
        private byte[] accumulatedHash;
        private byte[] signature;
        private int lastSequenceNumber;
        private int lastRecordLength;

        LogInfo(File logFile, LogFileHeaderInfo logFileHeaderInfo){
            this.logFile = logFile;
            this.logFileHeaderInfo = logFileHeaderInfo;
        }

        byte[] getSignature() {
            return signature;
        }

        byte[] getAccumulatedHash() {
            return accumulatedHash;
        }

        int getLastSequenceNumber() {
            return lastSequenceNumber;
        }

        File getLogFile() {
            return logFile;
        }

        AccumulativeDigest getAccumulativeDigest() {
            return logFileHeaderInfo.accumulativeDigest;
        }

        int getLastRecordLength() {
            return lastRecordLength;
        }

        void updateLastRecord(LogReaderRecord record) {
            this.lastSequenceNumber = record.getSequenceNumber();
            this.lastRecordLength = record.getRecordLength();
        }
    }

    static class LogFileHeaderInfo {
        private final AccumulativeDigest accumulativeDigest;
        private final SecretKey secretKey;
        private final Certificate signingCertificate;
        private final byte[] headerSignature;
        private final String lastFileName;
        private final byte[] lastFileHash;
        private final byte[] lastSignature;

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

    private static class SimpleCheckLogFileRecordListener extends LogReaderRecordListener {
        SimpleCheckLogFileRecordListener(){
            super(true);
        }

        @Override
        protected void handleRecordAdded(LogReaderRecord record) {
        }
    }

    private static class OutputtingLogFileRecordListener extends LogReaderRecordListener {
        final OutputStream out;
        OutputtingLogFileRecordListener(OutputStream out){
            super(true);
            this.out = out;
        }

        protected void handleRecordAdded(LogReaderRecord record) {
            StringBuffer sb = new StringBuffer();
            sb.append("Sequence Number: " + record.getSequenceNumber() + "\n");
            sb.append("Record Type: " + record.getRecordType() + "\n");
            sb.append("Encryption Type: " + record.getEncryptionType() + "\n");
            sb.append("Timestamp: " + record.getTimestamp() + "\n");
            sb.append("Last Record Length: " + record.getLastRecordLength() + "\n");
            sb.append("Record Length: " + record.getRecordLength() + "\n");
            sb.append("\n");
            try {
                out.write(sb.toString().getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}


