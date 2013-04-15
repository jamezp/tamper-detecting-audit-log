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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class AccumulativeDigest {

    private final HashAlgorithm hashAlgorithm;
    private final MessageDigest currentDigest;
    private final MessageDigest accumulativeDigest;
    private final byte[] secureRandomBytes;

    private AccumulativeDigest(HashAlgorithm hashAlgorithm, final byte[] secureRandomBytes) {
        this.hashAlgorithm = hashAlgorithm;
        this.accumulativeDigest = createMessageDigest();
        this.secureRandomBytes = secureRandomBytes;
        this.currentDigest = createMessageDigest();
    }

    static AccumulativeDigest createForWriter(HashAlgorithm hashAlgorithm, final byte[] secureRandomBytes) {
        return new AccumulativeDigest(hashAlgorithm, secureRandomBytes);
    }

    static AccumulativeDigest createForReader(HashAlgorithm hashAlgorithm, final File file) {
        AccumulativeDigest accumulativeDigest = new AccumulativeDigest(hashAlgorithm, new byte[IoUtils.SECURE_RANDOM_BYTES_LENGTH]);
        accumulativeDigest.resetForNewFile(file);
        return accumulativeDigest;
    }

    HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    void resetForNewFile(File file) {
        accumulativeDigest.reset();
        accumulativeDigest.update(file.getName().getBytes());
    }

    void setSecureRandomBytesForReading(byte[] secureRandomBytes) {
        System.arraycopy(secureRandomBytes, 0, this.secureRandomBytes, 0, secureRandomBytes.length);
    }

    byte[] digestRecord(RecordType recordType, byte[] header, byte[] body) {
        currentDigest.reset();
        currentDigest.update(header);
        currentDigest.update(body);
        currentDigest.update(secureRandomBytes);
        byte[] digest = currentDigest.digest();

        if (recordType.addToAccumulativeDigest()) {
            accumulativeDigest.update(header);
            accumulativeDigest.update(body);
            accumulativeDigest.update(digest);
        }
        return digest;
    }

    byte[] digestRecordAndCheck(RecordType recordType, byte[] header, byte[] body, byte[] hash) {
        byte[] ourHash = digestRecord(recordType, header, body);
        if (!Arrays.equals(hash, ourHash)) {
            throw new IllegalStateException("Bad hash for record");
        }
        return hash;
    }

    byte[] getAccumulativeHash() {
        try {
            MessageDigest clone = (MessageDigest)accumulativeDigest.clone();
            return clone.digest();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    private MessageDigest createMessageDigest() {
        try {
            return MessageDigest.getInstance(hashAlgorithm.toString());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
