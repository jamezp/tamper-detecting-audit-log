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
import java.io.IOException;
import java.io.RandomAccessFile;

public class LogReaderRecord {
    private final byte[] header;
    private final byte[] body;
    private final byte[] hash;

    private LogReaderRecord(byte[] header, byte[] body, byte[] hash) {
        this.header = header;
        this.body = body;
        this.hash = hash;
    }

    public int getSequenceNumber() {
        return HeaderUtil.getSequenceNumber(header);
    }


    public RecordType getRecordType() {
        return RecordType.fromByte(HeaderUtil.getRecordTypeByte(header));
    }

    public EncryptionType getEncryptionType() {
        return EncryptionType.fromByte(HeaderUtil.getEncryptionTypeByte(header));
    }

    public long getTimestamp() {
        return HeaderUtil.getTimeStamp(header);
    }

    public int getRecordLength() {
        return HeaderUtil.getCurrentLength(header);
    }

    public int getLastRecordLength() {
        return HeaderUtil.getLastLength(header);
    }

    public byte[] getHeader() {
        return header;
    }

    public byte[] getBody() {
        return body;
    }

    public byte[] getHash() {
        return hash;
    }

    static LogReaderRecord readHashAlgorithm(File file, RandomAccessFile raf) {
        try {
            final byte[] header = LogReaderRecord.readLogRecordHeader(raf);
            if (header == null) {
                throw new IllegalStateException("Could not find hash algorithm header");
            }
            //int recordLength = getRecordLength(header);
            if (HeaderUtil.getRecordTypeByte(header) != RecordType.HASH_ALGORITHM.getByteValue()) {
                throw new IllegalStateException("Could not find hash algorithm header");
            }
            final byte[] body = readRecordBody(raf, 0, 1);
            final HashAlgorithm hashAlgorithm = HashAlgorithm.fromByte(body[0]);
            final byte[] hash = readRecordHash(raf, hashAlgorithm);
            return new LogReaderRecord(header, body, hash);
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException)e;
            }
            throw new RuntimeException(e);
        }
    }

    static LogReaderRecord read(RandomAccessFile raf, AccumulativeDigest accumulativeDigest) {
        final byte[] header = readLogRecordHeader(raf);
        if (header == null) {
            return null;
        }
        final int recordLength = getRecordLength(header);
        final byte[] body = readRecordBody(raf, 0, recordLength - accumulativeDigest.getHashAlgorithm().getHashLength() - IoUtils.HEADER_LENGTH);
        final byte[] hash = readRecordHash(raf, accumulativeDigest.getHashAlgorithm());

        LogReaderRecord logRecord = new LogReaderRecord(header, body, hash);
        return logRecord;
    }


    private static byte[] readRecordBody(RandomAccessFile raf, int offset, int length) {
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

    private static byte[] readLogRecordHeader(RandomAccessFile raf) {
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
        return HeaderUtil.bytesToInt(header, 22);
    }
}