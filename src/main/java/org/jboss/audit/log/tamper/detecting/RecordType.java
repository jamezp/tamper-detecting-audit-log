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
enum RecordType {
    SECRET_RANDOM_NUMBER((byte)0x01, true),
    SYMMETRIC_ENCRYPTION_KEY((byte)0x02, true),
    LAST_FILE((byte)0x03, true),
    CLIENT_LOG_DATA((byte)0x04, true),
    ACCUMULATED_HASH((byte)0x05, false),
    LOG_FILE_SIGNATURE((byte)0x06, false),
    CERTIFICATE((byte)0x07, true),
    STARTUP((byte)0x08, true),
    SHUTDOWN((byte)0x09, true),
    UNAUTHORIZED_CONNECTION_ATTEMPT((byte)0x0a, true), //is this necessary
    AUDITOR_NOTIFICATION((byte)0x0b, true),
    HEARTBEAT((byte)0x0c, true),
    CLIENT_ID((byte)0x0d, true),
    HASH_ALGORITHM((byte)0x0e, true),
    HEADER_SIGNATURE((byte)0x0f, true);

    private final byte value;
    private final boolean addToAccumulativeDigest;

    RecordType(byte value, boolean addToAccumulativeDigest){
        this.value = value;
        this.addToAccumulativeDigest = addToAccumulativeDigest;
    }

    byte getByteValue() {
        return value;
    }

    boolean addToAccumulativeDigest() {
        return addToAccumulativeDigest;
    }

    static RecordType fromByte(byte b) {
        switch (b) {
        case 0x01:
            return SECRET_RANDOM_NUMBER;
        case 0x02:
            return SYMMETRIC_ENCRYPTION_KEY;
        case 0x03:
            return LAST_FILE;
        case 0x04:
            return CLIENT_LOG_DATA;
        case 0x05:
            return ACCUMULATED_HASH;
        case 0x06:
            return LOG_FILE_SIGNATURE;
        case 0x07:
            return CERTIFICATE;
        case 0x08:
            return STARTUP;
        case 0x09:
            return SHUTDOWN;
        case 0x0a:
            return UNAUTHORIZED_CONNECTION_ATTEMPT;
        case 0x0b:
            return AUDITOR_NOTIFICATION;
        case 0x0c:
            return HEARTBEAT;
        case 0x0d:
            return CLIENT_ID;
        case 0x0e:
            return HASH_ALGORITHM;
        case 0x0f:
            return HEADER_SIGNATURE;
        default:
            throw new IllegalArgumentException("Unknown record type: " + b);
        }
    }
}
