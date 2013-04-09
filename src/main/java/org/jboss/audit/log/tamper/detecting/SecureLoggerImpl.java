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
import java.util.concurrent.BlockingQueue;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class SecureLoggerImpl implements SecureLogger {
    private final BlockingQueue<LogRecord> recordQueue;
    private final LogWriter logWriter;

    private SecureLoggerImpl(BlockingQueue<LogRecord> recordQueue, LogWriter logWriter) {
        this.recordQueue = recordQueue;
        this.logWriter = logWriter;
    }

    static SecureLogger create(KeyManager securityFacade, File logFileDir, BlockingQueue<LogRecord> recordQueue) {
        LogWriter writer = LogWriter.create(securityFacade, logFileDir, recordQueue);
        SecureLoggerImpl logger = new SecureLoggerImpl(recordQueue, writer);
        logger.initialize();
        return logger;
    }

    private void initialize() {
        //TODO verify the previous log files etc.
        Thread t = new Thread(logWriter, "audit-log-writer");
        t.start();
    }

    @Override
    public void logMessage(byte[] message) {
        recordQueue.add(new LogRecord(message, RecordType.CLIENT_LOG_DATA));
    }


    //TODO heart beat
}
