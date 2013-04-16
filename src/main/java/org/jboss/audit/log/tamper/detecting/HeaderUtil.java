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

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class HeaderUtil {

    static byte[] createHeader(RecordType type, EncryptionType encryptionType, int lastLength, int currentLength, int currentSequenceNumber) {
        byte[] header = new byte[IoUtils.HEADER_LENGTH];
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

    static int getSequenceNumber(byte[] header) {
        return bytesToInt(header, 4);
    }

    static byte getRecordTypeByte(byte[] header) {
        return header[8];
    }

    static byte getEncryptionTypeByte(byte[] header) {
        return header[9];
    }

    static long getTimeStamp(byte[] header) {
        return bytesToLong(header, 10);
    }

    static int getLastLength(byte[] header) {
        return bytesToInt(header, 18);
    }

    static int getCurrentLength(byte[] header) {
        return bytesToInt(header, 22);
    }

    private static void appendInt4Bytes(byte[] bytes, int pos, int value) {
        for (int i = 0; i < 4; i++) {
            int offset = (4 - 1 - i) * 8;
            bytes[i + pos] = (byte) ((value >>> offset) & 0xFF);
        }
    }

    static byte[] intToByteArray(int value) {
        byte[] bytes = new byte[4];
        appendInt4Bytes(bytes, 0, value);
        return bytes;
    }

    private static void appendLong8Bytes(byte[] bytes, int pos, long value) {
        for (int i = 0; i < 8; i++) {
            int offset = (8 - 1 - i) * 8;
            bytes[i + pos] = (byte) ((value >>> offset) & 0xFF);
        }
    }

    static int bytesToInt(byte[] bytes, int pos) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (bytes[i + pos] & 0x000000FF) << shift;
        }
        return value;
    }

    private static long bytesToLong(byte[] bytes, int pos) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            int shift = (8 - 1 - i) * 8;
            value += ( (long)(bytes[i + pos] & 0x00000000000000FF) << shift );
        }
        return value;
    }

}
