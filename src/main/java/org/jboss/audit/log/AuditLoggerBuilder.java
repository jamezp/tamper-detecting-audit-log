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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;

import org.jboss.logmanager.Level;
import org.jboss.logmanager.handlers.SyslogHandler;
import org.jboss.logmanager.handlers.SyslogHandler.Facility;
import org.jboss.logmanager.handlers.SyslogHandler.SyslogType;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class AuditLoggerBuilder<T extends AuditLoggerBuilder<T>> {

    protected final File logFileDir;
    protected volatile SyslogAppender syslogAppender;

    protected AuditLoggerBuilder(File logFileDir) {
        this.logFileDir = logFileDir;
    }

    public SyslogAppenderBuilder<T> createSyslogAppenderBuilder(){
        return new SyslogAppenderBuilder<T>();
    }

    public class SyslogAppenderBuilder<T extends AuditLoggerBuilder<T>> {

        private InetAddress serverAddress = SyslogHandler.DEFAULT_ADDRESS;
        private int port = SyslogHandler.DEFAULT_PORT;
        private String appName;
        private String hostname;
        private Facility facility = SyslogHandler.DEFAULT_FACILITY;
        private SyslogType syslogType;
        private Level level = Level.INFO;

        public SyslogAppenderBuilder<T> setServerAddress(InetAddress serverAddress){
            this.serverAddress = serverAddress;
            return this;
        }

        public SyslogAppenderBuilder<T> setPort(int port){
            this.port = port;
            return this;
        }

        //TODO this is not configurable in the underlying SyslogHandler
        public SyslogAppenderBuilder<T> setAppName(String appName) {
            this.appName = appName;
            return this;
        }

        public SyslogAppenderBuilder<T> setFacility(Facility facility){
            this.facility = facility;
            return this;
        }

        public SyslogAppenderBuilder<T> setSyslogType(SyslogType syslogType){
            this.syslogType = syslogType;
            return this;
        }

        public SyslogAppenderBuilder<T> setLogLevel(Level level){
            this.level = level;
            return this;
        }

        public T done() {
            SyslogHandler syslogHandler;
            try {
                syslogHandler = new SyslogHandler(serverAddress, port, facility, syslogType, hostname);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            syslogAppender = new SyslogAppender(syslogHandler, level);
            return (T)AuditLoggerBuilder.this;
        }
    }
}
