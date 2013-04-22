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
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

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
    LogInfo checkLogFile() throws ValidationException {
        return readLogFile(new SimpleCheckLogFileRecordListener(keyManager.getEncryptingPrivateKey(), keyManager.getViewingPrivateKey()));
    }


    void verifyLogFile(OutputStream out) throws ValidationException {
        LogInfo logInfo = readLogFile(new VerifyingLogFileRecordListener(keyManager.getEncryptingPrivateKey(), keyManager.getViewingPrivateKey(), out));
    }


    LogInfo readLogFile(LogReaderRecordListener listener) throws ValidationException {
        final RandomAccessFile raf;
        try {
            raf = new RandomAccessFile(logFile, "r");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        try {
            readLogFileHeader(logFile, raf, listener);
            final LogInfo logInfo = new LogInfo(logFile, listener);
            final HashAlgorithm hashAlgorithm = listener.getAccumulativeDigest().getHashAlgorithm();
            while (true) {
                final LogReaderRecord logRecordInfo = LogReaderRecord.read(raf, hashAlgorithm);
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

                    final LogReaderRecord signatureInfo = LogReaderRecord.read(raf, hashAlgorithm);
                    if (signatureInfo != null) {
                        logInfo.updateLastRecord(signatureInfo);
                        listener.recordAdded(signatureInfo);
                        checkRecordType(signatureInfo, RecordType.LOG_FILE_SIGNATURE);
                        logInfo.signature = signatureInfo.getBody();
                        if (LogReaderRecord.read(raf, hashAlgorithm) != null) {
                            listener.logOrThrowException("Unknown content at the end of the file");
                        }

                        if (!Arrays.equals(logInfo.accumulatedHash, listener.getAccumulativeDigest().getAccumulativeHash())) {
                            listener.logOrThrowException("The calculated accumulative hash was different from the accumulative hash record");
                        }

                        byte[] calculatedSignature = null;
                        try {
                            Signature signature = Signature.getInstance(keyManager.getSigningAlgorithmName());
                            signature.initSign(keyManager.getSigningPrivateKey());
                            signature.update(listener.getAccumulativeDigest().getAccumulativeHash());
                            calculatedSignature = signature.sign();
                        } catch(Exception e) {
                            listener.logOrThrowException("Could not calculate signature", e);
                        }
                        if (!Arrays.equals(calculatedSignature, logInfo.signature)) {
                            listener.logOrThrowException("Signature differs");
                        }
                    }

                    return logInfo;
                }
            }

        } finally {
            IoUtils.safeClose(raf);
        }
    }

    private void readLogFileHeader(File logFile, RandomAccessFile raf, LogReaderRecordListener listener) throws ValidationException {
        //Read hash algorithm
        LogReaderRecord hashAlgorithmRecord = LogReaderRecord.readHashAlgorithm(logFile, raf);
        final HashAlgorithm hashAlgorithm = HashAlgorithm.fromByte(hashAlgorithmRecord.getBody()[0]);
        final AccumulativeDigest accumulativeDigest = AccumulativeDigest.createForReader(hashAlgorithm, logFile);
        listener.initializeHashAlgorithm(hashAlgorithmRecord, accumulativeDigest);

        //Secure random number
        listener.initializeSecureRandomNumber(LogReaderRecord.read(raf, hashAlgorithm));

        //Read the symmetric encryption keys
        listener.initializeEncryptionSymmetricKey(LogReaderRecord.read(raf, hashAlgorithm));
        listener.initializeViewingSymmetricKey(LogReaderRecord.read(raf, hashAlgorithm));

        //Read the signing certificate
        listener.initializeSigningCertificate(LogReaderRecord.read(raf, hashAlgorithm));

        //Read the header signature
        listener.initializeHeaderSignature(LogReaderRecord.read(raf, hashAlgorithm));

        //Read the last file name, hash and signature
        listener.initializeLastFile(LogReaderRecord.read(raf, hashAlgorithm));
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
        private final LogReaderRecordListener listener;
        private byte[] accumulatedHash;
        private byte[] signature;
        private int lastSequenceNumber;
        private int lastRecordLength;

        LogInfo(File logFile, LogReaderRecordListener listener){
            this.logFile = logFile;
            this.listener = listener;
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
            return listener.getAccumulativeDigest();
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
        SimpleCheckLogFileRecordListener(PrivateKey encryptingPrivateKey, PrivateKey viewingPrivateKey){
            super(encryptingPrivateKey, viewingPrivateKey);
        }

        @Override
        protected void handleRecordAdded(LogReaderRecord record, byte[] calculatedHashForRecord) {
        }

        @Override
        protected void logOrThrowException(String message) throws ValidationException {
            throw new ValidationException(message);
        }

        @Override
        protected void logOrThrowException(String message, Throwable cause) throws ValidationException {
            throw new ValidationException(message, cause);
        }
    }

    private static class VerifyingLogFileRecordListener extends LogReaderRecordListener {
        private long lastTimeStamp = -1;
        private int lastSequenceNumber;
        private final OutputStream out;

        VerifyingLogFileRecordListener(PrivateKey encryptingPrivateKey, PrivateKey viewingPrivateKey, OutputStream out){
            super(encryptingPrivateKey, viewingPrivateKey);
            this.out = out;
        }

        protected void handleRecordAdded(LogReaderRecord record, byte[] calculatedHashForRecord) {
            StringBuffer sb = new StringBuffer();
            if (lastTimeStamp != -1) {
                sb.append("\n");
            }

            List<String> errors = null;

            int sequenceNumber = record.getSequenceNumber();
            sb.append("Sequence Number: " + sequenceNumber + "\n");
            if (lastSequenceNumber != sequenceNumber - 1) {
                errors = appendError(errors, "Expected sequence number " + lastSequenceNumber + 1);
            }
            lastSequenceNumber = sequenceNumber;

            sb.append("Record Type: " + record.getRecordType() + "\n");
            sb.append("Encryption Type: " + record.getEncryptionType() + "\n");

            long timestamp = record.getTimestamp();
            sb.append("Timestamp: " + timestamp + "\n");
            if (timestamp <= lastTimeStamp) {
                errors = appendError(errors, "Expected a timestamp greater than " + lastTimeStamp);
            }
            lastTimeStamp = timestamp;


            sb.append("Last Record Length: " + record.getLastRecordLength() + "\n");
            sb.append("Record Length: " + record.getRecordLength() + "\n");

            if (calculatedHashForRecord != record.getHash()) {
                errors = appendError(errors, "Wrong has for record. The calculated one should be " + calculatedHashForRecord + ", while it was " + record.getHash());
            }

            if (errors != null) {
                sb.append("--- Errors ---\n");
                for (String error : errors) {
                    sb.append(error + "\n");
                }
            }

            sb.append("\n");

            try {
                out.write(sb.toString().getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void logOrThrowException(String message) throws ValidationException {
            try {
                out.write(message.getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void logOrThrowException(String message, Throwable cause) throws ValidationException {
            try {
                out.write(message.getBytes());
                PrintStream ps = new PrintStream(out);
                try {
                    cause.printStackTrace();
                } finally {
                    IoUtils.safeClose(ps);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private List<String> appendError(List<String> errors, String error){
            if (errors == null) {
                errors = new ArrayList<String>();
            }
            errors.add(error);
            return errors;
        }

    }
}


