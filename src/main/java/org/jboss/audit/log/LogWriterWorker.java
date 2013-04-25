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
package org.jboss.audit.log;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;


/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
final class LogWriterWorker<T extends LogWriterRecord> implements Runnable {
    private volatile boolean cycleLog;

    private final int heartbeatIntervalSeconds;
    private final LogWriter<T> logWriter;
    private final BlockingQueue<T> recordQueue = new ArrayBlockingQueue<T>(1000);

    //Thread status fields, guarded by 'this'
    private volatile AuditLogWriterStatus loggerStatus = AuditLogWriterStatus.RUNNING;
    private int queuedMessages;
    private AuditLogger.ClosedCallback closedCallback;

    private LogWriterWorker(LogWriter<T> logWriter, int heartbeatIntervalSeconds) {
        this.logWriter = logWriter;
        this.heartbeatIntervalSeconds = heartbeatIntervalSeconds;
    }

    static <T extends LogWriterRecord> LogWriterWorker<T> create(LogWriter<T> logWriter, int heartbeatIntervalSeconds) {
        return new LogWriterWorker<T>(logWriter, heartbeatIntervalSeconds);
    }

    void logMessage(byte[] message) {
        synchronized (this) {
            if (loggerStatus == AuditLogWriterStatus.SHUTDOWN) {
                throw new IllegalStateException("Logger was shut down");
            } else if (loggerStatus == AuditLogWriterStatus.ERROR) {
                return;
            }
            queuedMessages++;
        }
        recordQueue.add(logWriter.createLogRecord(message));
    }


    AuditLogWriterStatus getStatus() {
        return loggerStatus;
    }

    public void close(AuditLogger.ClosedCallback closedCallback) {
        synchronized (this) {
            this.closedCallback = closedCallback;
            loggerStatus = AuditLogWriterStatus.SHUTDOWN;
        }
    }


    @Override
    public void run() {
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    boolean shouldShutdown = false;
                    AuditLogger.ClosedCallback closedCallback = null;
                    synchronized (LogWriterWorker.this) {
                        if (loggerStatus == AuditLogWriterStatus.SHUTDOWN && queuedMessages == 0) {
                            shouldShutdown = true;
                            closedCallback = this.closedCallback;
                        }
                    }
                    if (shouldShutdown) {
                        //Finalize log
                        logWriter.close();
                        closedCallback.closed();
                        return;
                    }

                    T record = heartbeatIntervalSeconds >= 0 ? recordQueue.poll(1, TimeUnit.SECONDS) : recordQueue.take();
                    if (record != null) {
                        synchronized (LogWriterWorker.this) {
                            queuedMessages--;
                        }
                        logWriter.logRecord(record);
                    } else {
                        //Log heartbeat
                        logWriter.writeHeartbeat();
                    }

                    if (cycleLog) {
                        logWriter.cycleLog();
                    }
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
        } catch(Exception e) {
            loggerStatus = AuditLogWriterStatus.ERROR;
        } finally {
            //Close the log
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }
}