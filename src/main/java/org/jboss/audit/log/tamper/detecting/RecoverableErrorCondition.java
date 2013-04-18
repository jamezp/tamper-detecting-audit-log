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

import java.util.Arrays;
import java.util.EnumSet;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public enum RecoverableErrorCondition {

    TRUSTED_LOCATION_DOES_NOT_EXIST(RecoverAction.CREATE_TRUSTED_LOCATION),
    TRUSTED_LOCATION_TAMPERED_WITH(RecoverAction.REBUILD_TRUSTED_LOCATION),
    TRUSTED_LOCATION_CURRENT_FILE_DOES_NOT_EXIST(RecoverAction.INSPECT_LAST_LOG_FILE),
    LAST_LOG_FILE_DOES_NOT_HAVE_AN_ACCUMULATED_HASH(RecoverAction.REPAIR_MISSING_ACCUMULATED_HASH),
    LAST_LOG_FILE_DOES_NOT_HAVE_A_SIGNATURE(RecoverAction.REPAIR_MISSING_SIGNATURE),
    POSSIBLE_CRASH_BETWEEN_WRITING_LOG_RECORD_AND_UPDATING_TRUSTED_LOCATION(RecoverAction.REPAIR_TRUSTED_LOCATION);


    private final EnumSet<RecoverAction> allowedActions;

    private RecoverableErrorCondition(RecoverAction...allowedActions) {
        EnumSet<RecoverAction> actions = EnumSet.copyOf(Arrays.asList(allowedActions));
        this.allowedActions = actions;
    }

    EnumSet<RecoverAction> getAllowedActions(){
        return allowedActions;
    }

    public enum RecoverAction {
        //Actions for TRUSTED_LOCATION_DOES_NOT_EXIST
        CREATE_TRUSTED_LOCATION,
        //Actions for TRUSTED_LOCATION_TAMPERED_WITH
        REBUILD_TRUSTED_LOCATION,
        //Actions for TRUSTED_LOCATION_CURRENT_FILE_DOES_NOT_EXIST
        INSPECT_LAST_LOG_FILE,
        //Actions for LAST_LOG_FILE_DOES_NOT_HAVE_AN_ACCUMULATED_HASH
        REPAIR_MISSING_ACCUMULATED_HASH,
        //Actions for LAST_LOG_FILE_DOES_NOT_HAVE_A_SIGNATURE
        REPAIR_MISSING_SIGNATURE,
        //Actions for POSSIBLE_CRASH_BETWEEN_WRITING_LOG_RECORD_AND_UPDATING_TRUSTED_LOCATION
        REPAIR_TRUSTED_LOCATION;
    }
}
