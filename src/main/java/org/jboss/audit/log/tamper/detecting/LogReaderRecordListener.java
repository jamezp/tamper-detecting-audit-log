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
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
abstract class LogReaderRecordListener {

    private final File logFile;
    private final PrivateKey encryptingPrivateKey;
    private final PrivateKey viewingPrivateKey;
    private final String signingAlgorithmName;
    private final PrivateKey signingPrivateKey;
    private final boolean maintainHash;

    //Info read
    private volatile AccumulativeDigest accumulativeDigest;
    private volatile SecretKey secretKey;
    private volatile Certificate signingCertificate;
    private volatile String lastFileName;
    private volatile byte[] lastFileHash;
    private volatile byte[] lastFileSignature;
    private volatile byte[] accumulatedHashFromRecord;
    private volatile byte[] signatureFromRecord;
    private volatile int sequenceNumber;
    private volatile int recordLength;



    protected LogReaderRecordListener(File logFile, PrivateKey encryptingPrivateKey, PrivateKey viewingPrivateKey, String signingAlgorithmName, PrivateKey signingPrivateKey) {
        this.logFile = logFile;
        this.encryptingPrivateKey = encryptingPrivateKey;
        this.viewingPrivateKey = viewingPrivateKey;
        this.signingAlgorithmName = signingAlgorithmName;
        this.signingPrivateKey = signingPrivateKey;
        maintainHash = encryptingPrivateKey != null;
    }

    AccumulativeDigest getAccumulativeDigest() {
        return accumulativeDigest;
    }

    byte[] getSignatureFromRecord() {
        return signatureFromRecord;
    }

    byte[] getAccumulatedHashFromRecord() {
        return accumulatedHashFromRecord;
    }

    int getSequenceNumber() {
        return sequenceNumber;
    }

    File getLogFile() {
        return logFile;
    }

    int getRecordLength() {
        return recordLength;
    }

    final void initializeHashAlgorithm(final LogReaderRecord record, final AccumulativeDigest accumulativeDigest) throws ValidationException {
        this.accumulativeDigest = accumulativeDigest;
        hashAndHandleRecordAdded(record);
    }

    final void initializeSecureRandomNumber(final LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.SECRET_RANDOM_NUMBER);
        if (maintainHash) {
            final byte[] secureRandomBytes = LogReader.decryptMessageUsingPrivateKey(record.getBody(), encryptingPrivateKey);
            accumulativeDigest.setSecureRandomBytesForReading(secureRandomBytes);
        }
        hashAndHandleRecordAdded(record);
    }

    final void initializeEncryptionSymmetricKey(LogReaderRecord record) throws ValidationException {
        //Read the symmetric encryption keys
        checkRecordType(record, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        if (viewingPrivateKey == null && encryptingPrivateKey != null) {
            secretKey = decryptSymmetricEncryptionKey(record, encryptingPrivateKey);
        }
        hashAndHandleRecordAdded(record);
    }

    final void initializeViewingSymmetricKey(LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        if (viewingPrivateKey != null) {
            secretKey = decryptSymmetricEncryptionKey(record, viewingPrivateKey);
        } else if (encryptingPrivateKey == null) {
            logOrThrowException("No encrypting or viewing private key to decrypt the symmetric encryption key");
        }
        hashAndHandleRecordAdded(record);
    }

    final void initializeSigningCertificate(LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.CERTIFICATE);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            signingCertificate = cf.generateCertificate(new ByteArrayInputStream(record.getBody()));
        } catch (CertificateException e) {
            logOrThrowException("Could not read signing certificate", e);
        }
        hashAndHandleRecordAdded(record);
    }

    final void initializeHeaderSignature(LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.HEADER_SIGNATURE);
        //TODO do something with signature?
        final byte[] headerSignature = record.getBody();
        hashAndHandleRecordAdded(record);
    }

    final void initializeLastFile(LogReaderRecord record) throws ValidationException {
        //Read the last file name, hash and signature
        if (record.getRecordType() == RecordType.LAST_FILE) {
            final byte[] nameBytes = new byte[HeaderUtil.bytesToInt(record.getBody(), 0)];
            System.arraycopy(record.getBody(), 4, nameBytes, 0, nameBytes.length);
            lastFileName = new String(nameBytes);
            lastFileHash = new byte[HeaderUtil.bytesToInt(record.getBody(), 4 + nameBytes.length)];
            System.arraycopy(record.getBody(), 8 + nameBytes.length, lastFileHash, 0, lastFileHash.length);
            if (new String(lastFileHash).equals("null")) {
                lastFileName = null;
            }
            lastFileSignature = new byte[HeaderUtil.bytesToInt(record.getBody(), 8 + nameBytes.length + lastFileHash.length)];
            System.arraycopy(record.getBody(), 12 + nameBytes.length + lastFileHash.length, lastFileSignature, 0, lastFileSignature.length);
        } else if (record.getRecordType() != RecordType.AUDITOR_NOTIFICATION) {
            throw new IllegalStateException("Expected to find last file information, type was " + record.getRecordType());
        }
        hashAndHandleRecordAdded(record);
    }

    private SecretKey decryptSymmetricEncryptionKey(LogReaderRecord logRecordInfo, PrivateKey privateKey) {
        byte[] rawKey = LogReader.decryptMessageUsingPrivateKey(logRecordInfo.getBody(), privateKey);
        if (rawKey == null) {
            throw new IllegalStateException("Could not decrypt symmetric encryption private key");
        }
        return new SecretKeySpec(rawKey, "AES");
    }

    final void recordAdded(LogReaderRecord record) throws ValidationException {
        final RecordType recordType = record.getRecordType();
        if (signatureFromRecord != null) {
            logOrThrowException("Unknown content at end of file");
        } else if (recordType == RecordType.ACCUMULATED_HASH) {
              if (accumulatedHashFromRecord != null) {
                  logOrThrowException("The type of the record is " + RecordType.ACCUMULATED_HASH + " which already has been seen");
              }
              accumulatedHashFromRecord = record.getBody();
              if (!Arrays.equals(accumulativeDigest.getAccumulativeHash(), accumulatedHashFromRecord)) {
                  logOrThrowException("The calculated accumulative hash was different from the accumulative hash record");
              }

        } else if (recordType == RecordType.LOG_FILE_SIGNATURE) {
            if (accumulatedHashFromRecord == null) {
                logOrThrowException("Found " + RecordType.LOG_FILE_SIGNATURE + " without having seen an " + RecordType.ACCUMULATED_HASH + " record");
            }
            signatureFromRecord = record.getBody();

            byte[] calculatedSignature = null;
            try {
                Signature signature = Signature.getInstance(signingAlgorithmName);
                signature.initSign(signingPrivateKey);
                signature.update(accumulativeDigest.getAccumulativeHash());
                calculatedSignature = signature.sign();
            } catch(Exception e) {
                logOrThrowException("Could not calculate signature for checking", e);
            }
            if (!Arrays.equals(calculatedSignature, signatureFromRecord)) {
                logOrThrowException("The signature calculated from the " + RecordType.ACCUMULATED_HASH + " is different from the one from the " + RecordType.LOG_FILE_SIGNATURE + " record.");
            }
        } else if (recordType == RecordType.CLIENT_LOG_DATA || recordType == RecordType.HEARTBEAT) {
            if (accumulatedHashFromRecord != null) {
                logOrThrowException("Did not expect any " + recordType + " after the " + RecordType.ACCUMULATED_HASH + " record");
            }
        } else if (recordType == RecordType.AUDITOR_NOTIFICATION) {
            //This is fine until before the LOG_FILE_SIGNATURE
        } else {
            logOrThrowException("Unexpected record type " + recordType);
        }

        hashAndHandleRecordAdded(record);
    }

    private void hashAndHandleRecordAdded(LogReaderRecord record) {
        byte[] hash = null;
        if (maintainHash) {
            hash = accumulativeDigest.digestRecord(record.getRecordType(), record.getHeader(), record.getBody());
        }
        sequenceNumber = record.getSequenceNumber();
        recordLength = record.getRecordLength();
        handleRecordAdded(record, hash);
    }

    private boolean checkRecordType(LogReaderRecord logRecordInfo, RecordType expectedType) throws ValidationException {
        if (logRecordInfo.getRecordType() != expectedType) {
            logOrThrowException("Expected record type " + expectedType + "(" + expectedType.getByteValue() + "), but was" +
                    logRecordInfo.getRecordType() + "(" + logRecordInfo.getRecordType().getByteValue() + ")");
            return false;
        }
        return true;
    }


    protected abstract void handleRecordAdded(LogReaderRecord record, byte[] calculatedHashForRecord);

    protected abstract void logOrThrowException(String message) throws ValidationException;

    protected abstract void logOrThrowException(String message, Throwable cause) throws ValidationException;

    protected abstract void unrecoverableError(Throwable t) throws ValidationException;

    protected abstract void finalizeErrors();
}
