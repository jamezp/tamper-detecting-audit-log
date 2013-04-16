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

class LogWriterRecord {
    private final byte[] data;
    private final RecordType type;
    private final Callback callback;

    LogWriterRecord(byte[] data, RecordType type) {
        this(data, type, null);
    }

    LogWriterRecord(byte[] data, RecordType type, Callback callback) {
        this.data = data;
        this.type = type;
        this.callback = callback;
    }

    byte[] getData() {
        return data;
    }

    RecordType getType() {
        return type;
    }

    void logged() {
        if (callback != null) {
            callback.handled();
        }
    }

    interface Callback {
        void handled();
    }
}