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
import java.io.RandomAccessFile;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

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
        return readLogFile(new SimpleCheckLogFileRecordListener(logFile, keyManager.getEncryptingPrivateKey(), keyManager.getViewingPrivateKey(), keyManager.getSigningAlgorithmName(), keyManager.getSigningPrivateKey()));
    }


    LogInfo verifyLogFile(OutputStream out, LogRecordBodyOutputter bodyOutputter) throws ValidationException {
        return readLogFile(new VerifyingLogFileRecordListener(logFile, keyManager.getEncryptingPrivateKey(), keyManager.getViewingPrivateKey(), keyManager.getSigningAlgorithmName(), keyManager.getSigningPrivateKey(), out, bodyOutputter));
    }

    public void viewLogFile(PrivateKey viewingPrivateKey, OutputStream out, LogRecordBodyOutputter bodyOutputter) {
        try {
            readLogFile(new ViewingLogFileRecordListener(logFile, viewingPrivateKey, out, bodyOutputter));
        } catch (ValidationException e) {
            e.printStackTrace();
            throw new IllegalStateException("An error happened trying to read the log file");
        }
    }

    private LogInfo readLogFile(LogReaderRecordListener listener) throws ValidationException {
        final RandomAccessFile raf;
        try {
            raf = new RandomAccessFile(logFile, "r");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        try {
            //Header records
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

            final LogInfo logInfo = new LogInfo(listener);
            while (true) {
                final LogReaderRecord logRecordInfo = LogReaderRecord.read(raf, hashAlgorithm);
                if (logRecordInfo == null) {
                    return logInfo;
                }
                listener.recordAdded(logRecordInfo);
            }
        } catch (ValidationException e) {
            throw e;
        } catch (Throwable t) {
            listener.unrecoverableError(t);
        } finally {
            listener.finalizeErrors();
            IoUtils.safeClose(raf);
        }
        return null;
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
        private final LogReaderRecordListener listener;

        LogInfo(LogReaderRecordListener listener){
            this.listener = listener;
        }

        byte[] getSignature() {
            return listener.getSignatureFromRecord();
        }

        byte[] getAccumulatedHash() {
            return listener.getAccumulatedHashFromRecord();
        }

        int getLastSequenceNumber() {
            return listener.getSequenceNumber();
        }

        File getLogFile() {
            return listener.getLogFile();
        }

        AccumulativeDigest getAccumulativeDigest() {
            return listener.getAccumulativeDigest();
        }

        int getLastRecordLength() {
            return listener.getRecordLength();
        }

        String getLastFileName() {
            return listener.getLastFileName();
        }

        byte[] getLastFileSignature() {
            return listener.getLastFileSignature();
        }

        byte[] getLastFileHash() {
            return listener.getLastFileHash();
        }
    }


    private static class SimpleCheckLogFileRecordListener extends LogReaderRecordListener {
        SimpleCheckLogFileRecordListener(File logFile, PrivateKey encryptingPrivateKey, PrivateKey viewingPrivateKey, String signingAlgorithmName, PrivateKey signingPrivateKey){
            super(logFile, encryptingPrivateKey, viewingPrivateKey, signingAlgorithmName, signingPrivateKey);
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

        @Override
        protected void unrecoverableError(Throwable t) throws ValidationException {
            throw new ValidationException("An unrecoverable error happened reading the log file", t);
        }

        @Override
        protected void finalizeErrors() {
            //Noop
        }
    }

    private static class VerifyingLogFileRecordListener extends LogReaderRecordListener {
        private final OutputStream out;
        private final LogRecordBodyOutputter bodyOutputter;
        private final List<ErrorInfo> errorsForCurrentRecord = new ArrayList<LogReader.ErrorInfo>();
        private long lastTimeStamp;
        private int lastSequenceNumber;
        private Throwable unrecoverableError;

        VerifyingLogFileRecordListener(File logFile, PrivateKey encryptingPrivateKey, PrivateKey viewingPrivateKey, String signingAlgorithmName, PrivateKey signingPrivateKey, OutputStream out, LogRecordBodyOutputter bodyOutputter){
            super(logFile, encryptingPrivateKey, viewingPrivateKey, signingAlgorithmName, signingPrivateKey);
            this.out = out;
            this.bodyOutputter = bodyOutputter;

            try {
                out.write(("---------- " + logFile + " ----------\n").getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        protected void handleRecordAdded(LogReaderRecord record, byte[] calculatedHashForRecord) {
            final StringBuffer header = new StringBuffer("\n");

            int sequenceNumber = record.getSequenceNumber();
            header.append("Sequence Number: " + sequenceNumber + "\n");
            if (lastSequenceNumber != sequenceNumber - 1) {
                errorsForCurrentRecord.add(new ErrorInfo("Expected sequence number " + lastSequenceNumber + 1, null));
            }
            lastSequenceNumber = sequenceNumber;

            header.append("Record Type: " + record.getRecordType() + "\n");
            header.append("Encryption Type: " + record.getEncryptionType() + "\n");

            long timestamp = record.getTimestamp();
            header.append("Timestamp: " + timestamp + "\n");
            if (timestamp < lastTimeStamp) {
                errorsForCurrentRecord.add(new ErrorInfo("Expected a timestamp greater than " + lastTimeStamp, null));
            }
            lastTimeStamp = timestamp;

            header.append("Last Record Length: " + record.getLastRecordLength() + "\n");
            header.append("Record Length: " + record.getRecordLength() + "\n");

            if (!Arrays.equals(calculatedHashForRecord, record.getHash())) {
                errorsForCurrentRecord.add(new ErrorInfo("Wrong hash for record. The calculated one should be " + Arrays.toString(calculatedHashForRecord) + ", while it was " + Arrays.toString(record.getHash()), null));
            }

            if (errorsForCurrentRecord.size() >  0) {
                header.append("--- Errors (" + errorsForCurrentRecord.size() + ")---\n");
                for (int i = 0 ; i < errorsForCurrentRecord.size() ; i++) {
                    header.append("#" + (i + 1) + "\n");
                    ErrorInfo error = errorsForCurrentRecord.get(i);
                    header.append(error.message + "\n");
                    if (error.cause != null) {
                        IoUtils.printStackTraceToOutputStream(error.cause, new OutputStream() {
                            @Override
                            public void write(int b) throws IOException {
                                header.append((char)b);
                            }
                        });
                    }
                }
                errorsForCurrentRecord.clear();
            }

            try {
                out.write(header.toString().getBytes());
                if (bodyOutputter != null && record.getRecordType() == RecordType.CLIENT_LOG_DATA) {
                    out.write("Data:\n".getBytes());
                    bodyOutputter.outputLogRecordBody(out, record.getBody());
                    out.write("\n".getBytes());
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void logOrThrowException(String message) {
            logOrThrowException(message, null);
        }

        @Override
        protected void logOrThrowException(String message, Throwable cause) {
            errorsForCurrentRecord.add(new ErrorInfo(message, cause));
        }

        @Override
        protected void unrecoverableError(Throwable t) throws ValidationException {
            unrecoverableError = t;
        }

        @Override
        protected void finalizeErrors() {
            if (errorsForCurrentRecord.size() > 0) {
                final StringBuffer sb = new StringBuffer();
                sb.append("--- Errors (" + errorsForCurrentRecord.size() + ")---\n");
                for (int i = 0 ; i < errorsForCurrentRecord.size() ; i++) {
                    sb.append("#" + (i + 1) + "\n");
                    ErrorInfo error = errorsForCurrentRecord.get(i);
                    sb.append(error.message + "\n");
                    if (error.cause != null) {
                        IoUtils.printStackTraceToOutputStream(error.cause, new OutputStream() {
                            @Override
                            public void write(int b) throws IOException {
                                sb.append((char)b);
                            }
                        });
                    }
                }
                try {
                    out.write(sb.toString().getBytes());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            if (unrecoverableError != null) {
                IoUtils.printStackTraceToOutputStream(unrecoverableError, out);
            }
        }
    }

    private class ViewingLogFileRecordListener extends LogReaderRecordListener {
        private final LogRecordBodyOutputter bodyOutputter;
        private final OutputStream out;
        public ViewingLogFileRecordListener(File logFile, PrivateKey viewingPrivateKey, OutputStream out, LogRecordBodyOutputter bodyOutputter) {
            super(logFile, null, viewingPrivateKey, null, null);
            this.bodyOutputter = bodyOutputter;
            this.out = out;
        }

        @Override
        protected void handleRecordAdded(LogReaderRecord record, byte[] calculatedHashForRecord) throws ValidationException {
            if (record.getRecordType() == RecordType.CLIENT_LOG_DATA) {
                byte[] body = record.getBody();
                if (record.getEncryptionType() == EncryptionType.SYMMETRIC) {
                    body = decryptSymmetricLogMessage(record);
                }
                try {
                    bodyOutputter.outputLogRecordBody(out, body);
                    out.write("\n".getBytes());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        @Override
        protected void logOrThrowException(String message) throws ValidationException {
            throw new ValidationException(message);
        }

        @Override
        protected void logOrThrowException(String message, Throwable cause) throws ValidationException {
            throw new ValidationException(message, cause);
        }

        @Override
        protected void unrecoverableError(Throwable t) throws ValidationException {
            throw new ValidationException("Unrecoverable error", t);
        }

        @Override
        protected void finalizeErrors() {
        }

    }


    private static class ErrorInfo {
        private final String message;
        private final Throwable cause;

        public ErrorInfo(String message, Throwable cause) {
            this.message = message;
            this.cause = cause;
        }

    }
}


