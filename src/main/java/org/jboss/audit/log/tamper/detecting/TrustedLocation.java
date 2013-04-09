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

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class TrustedLocation {

    private final File trustedLocation;
    private final File logFileRoot;
    private volatile String previousLogFileName;
    private volatile String currentInspectionLogFileName;
    private volatile byte[] accumulativeHash;

    TrustedLocation(File logFileRoot, File trustedLocation) {
        this.logFileRoot = logFileRoot;
        this.trustedLocation = trustedLocation;
    }


    TrustedLocation initialize(File logFileRoot, File location) {
        TrustedLocation trustedLocation = new TrustedLocation(logFileRoot, location);
        trustedLocation.initialize();
        return trustedLocation;
    }

    private void initialize() {
        //TODO take action depending on whether trustedLocation exists or not
        //For now assume we start from a crash

        this.previousLogFileName = null;
        this.currentInspectionLogFileName = null;
        this.accumulativeHash = null;
    }

}
