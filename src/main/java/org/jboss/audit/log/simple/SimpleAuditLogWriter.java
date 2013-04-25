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
package org.jboss.audit.log.simple;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

import org.jboss.audit.log.LogFileNameUtil;
import org.jboss.audit.log.LogWriter;
import org.jboss.audit.log.LogWriterRecord;
import org.jboss.audit.log.simple.SimpleAuditLogWriter.SimpleAuditLogWriterRecord;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class SimpleAuditLogWriter implements LogWriter<SimpleAuditLogWriterRecord> {

    private final LogFileNameUtil logFileNameUtil;
    private volatile File logFile;
    private volatile RandomAccessFile currentRandomAccessFile;

    private SimpleAuditLogWriter(File logFileDir) {
        logFileNameUtil = new LogFileNameUtil(logFileDir);
    }


    static SimpleAuditLogWriter create(File logFileDir) {
        SimpleAuditLogWriter writer = new SimpleAuditLogWriter(logFileDir);
        writer.createNewLogFile();
        return writer;
    }


    private File createNewLogFile() {
        logFile = logFileNameUtil.generateNewLogFileName();
        try {
            logFile.createNewFile();
        } catch (IOException e1) {
            throw new RuntimeException(e1);
        }
        try {
            currentRandomAccessFile = new RandomAccessFile(logFile, "rwd");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }


        return logFile;
    }

    @Override
    public SimpleAuditLogWriterRecord createLogRecord(byte[] message) {
        return new SimpleAuditLogWriterRecord(message);
    }

    @Override
    public void logRecord(SimpleAuditLogWriterRecord record) {
        try {
            currentRandomAccessFile.write(record.message);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void writeHeartbeat() {
    }

    @Override
    public void cycleLog() {
    }

    @Override
    public void close() {
    }

    static class SimpleAuditLogWriterRecord implements LogWriterRecord {
        private final byte[] message;

        public SimpleAuditLogWriterRecord(byte[] message) {
            this.message = message;
        }
    }
}
