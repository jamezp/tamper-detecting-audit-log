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
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
abstract class LogReaderRecordListener {

    private final PrivateKey encryptingPrivateKey;
    private final PrivateKey viewingPrivateKey;
    private volatile AccumulativeDigest accumulativeDigest;
    private volatile SecretKey secretKey;
    private volatile Certificate signingCertificate;
    private volatile String lastFileName;
    private volatile byte[] lastFileHash;
    private volatile byte[] lastFileSignature;


    protected LogReaderRecordListener(PrivateKey encryptingPrivateKey, PrivateKey viewingPrivateKey) {
        this.encryptingPrivateKey = encryptingPrivateKey;
        this.viewingPrivateKey = viewingPrivateKey;
    }

    final void initializeHashAlgorithm(final LogReaderRecord record, final AccumulativeDigest accumulativeDigest) {
        this.accumulativeDigest = accumulativeDigest;
        recordAdded(record);
    }

    final void initializeSecureRandomNumber(final LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.SECRET_RANDOM_NUMBER);
        final byte[] secureRandomBytes = LogReader.decryptMessageUsingPrivateKey(record.getBody(), encryptingPrivateKey);
        accumulativeDigest.setSecureRandomBytesForReading(secureRandomBytes);
        recordAdded(record);
    }

    final void initializeEncryptionSymmetricKey(LogReaderRecord record) throws ValidationException {
        //Read the symmetric encryption keys
        checkRecordType(record, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        if (viewingPrivateKey == null && encryptingPrivateKey != null) {
            secretKey = decryptSymmetricEncryptionKey(record, encryptingPrivateKey);
        }
        recordAdded(record);
    }

    final void initializeViewingSymmetricKey(LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.SYMMETRIC_ENCRYPTION_KEY);
        if (viewingPrivateKey != null) {
            secretKey = decryptSymmetricEncryptionKey(record, viewingPrivateKey);
        } else if (encryptingPrivateKey == null) {
            logOrThrowException("No encrypting or viewing private key to decrypt the symmetric encryption key");
        }
        recordAdded(record);
    }

    final void initializeSigningCertificate(LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.CERTIFICATE);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            signingCertificate = cf.generateCertificate(new ByteArrayInputStream(record.getBody()));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        recordAdded(record);
    }

    final void initializeHeaderSignature(LogReaderRecord record) throws ValidationException {
        checkRecordType(record, RecordType.HEADER_SIGNATURE);
        //TODO do something with signature?
        final byte[] headerSignature = record.getBody();
        recordAdded(record);
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
            throw new IllegalStateException("Expected to find last file information");
        }
        recordAdded(record);
    }

    private SecretKey decryptSymmetricEncryptionKey(LogReaderRecord logRecordInfo, PrivateKey privateKey) {
        byte[] rawKey = LogReader.decryptMessageUsingPrivateKey(logRecordInfo.getBody(), privateKey);
        if (rawKey == null) {
            throw new IllegalStateException("Could not decrypt symmetric encryption private key");
        }
        return new SecretKeySpec(rawKey, "AES");
    }

    final void recordAdded(LogReaderRecord record) {
        byte[] hash = accumulativeDigest.digestRecord(record.getRecordType(), record.getHeader(), record.getBody());
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

    AccumulativeDigest getAccumulativeDigest() {
        return accumulativeDigest;
    }
}
