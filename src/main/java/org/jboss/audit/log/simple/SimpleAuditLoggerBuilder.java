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

import org.jboss.audit.log.AuditLogger;
import org.jboss.audit.log.AuditLoggerBuilder;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class SimpleAuditLoggerBuilder extends AuditLoggerBuilder {

    private SimpleAuditLoggerBuilder(File logFileDir) {
        super(logFileDir);
    }

    public static SimpleAuditLoggerBuilder createBuilder(File logFileDir) {
        return new SimpleAuditLoggerBuilder(logFileDir);
    }


    public AuditLogger buildLogger() {
        //TODO make heartbeat configurable
        int heartbeat = 1;
        AuditLogger simpleAuditLogger = SimpleAuditLogger.create(logFileDir, heartbeat);
        return simpleAuditLogger;
    }
}
