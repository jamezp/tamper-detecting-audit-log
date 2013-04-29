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

import java.util.logging.Level;

import org.jboss.logmanager.ExtHandler;
import org.jboss.logmanager.ExtLogRecord;

/**
 * Internal class, create using {@link AuditLoggerBuilder#createSyslogAppenderBuilder()
 * }
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class SyslogAppender {

    final ExtHandler syslogHandler;
    final Level level;

    SyslogAppender(ExtHandler syslogHandler, Level level) {
        this.syslogHandler = syslogHandler;
        this.level = level;
    }

    public void logMessage(byte[] message) {
        //Syslog doesn't like things like line breaks in the text, so write a hex encoded string
        String formattedBytes = new String(message); //DatatypeConverter.printHexBinary(message);
        syslogHandler.publish(new ExtLogRecord(level, formattedBytes, SyslogAppender.class.getName()));
    }
}
