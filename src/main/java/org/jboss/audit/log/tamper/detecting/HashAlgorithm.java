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
public enum HashAlgorithm {
    SHA1((byte)0x00, 20),
    MD5((byte)0x01, 16),
    SHA256((byte)0x02, 32),
    SHA384((byte)0x03, 64),
    SHA512((byte)0x04, 64);

    private final byte value;
    private final int hashLength;

    private HashAlgorithm(byte value, int hashLength) {
        this.value = value;
        this.hashLength = hashLength;
    }

    byte getByteValue() {
        return value;
    }

    int getHashLength() {
        return hashLength;
    }

    static HashAlgorithm fromByte(byte b) {
        switch (b) {
        case 0x00:
            return SHA1;
        case 0x01:
            return MD5;
        case 0x02:
            return SHA256;
        case 0x03:
            return SHA384;
        case 0x04:
            return SHA512;
        default:
            throw new IllegalArgumentException("Unknown hash algorithm: " + b);
        }
    }
}
