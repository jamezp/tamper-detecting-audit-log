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
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import org.jboss.audit.log.tamper.detecting.RecoverableErrorCondition.RecoverAction;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class RecoverableErrorContext {

    private final EnumSet<RecoverAction> repairableActions;
    private final EnumSet<RecoverAction> repairedActions = EnumSet.noneOf(RecoverAction.class);

    //Some of the repair actions are complex so it is easier to come all the way out again
    //and start the checks again from scratch
    //Ones that recommend this need to set this flag to true, and the consuming code must return following the check
    boolean recheck;

    RecoverableErrorContext(Set<RecoverAction> actions){
        this.repairableActions = actions.isEmpty() ? null : EnumSet.copyOf(actions);
    }


    private void setRepaired(RecoverAction action) {
        repairedActions.add(action);
    }

    boolean isRecheck() {
        return recheck;
    }

    void resetRecheck() {
        recheck = false;
    }


    void trustedLocationDoesNotExistWhileLogFilesExist(File trustedLocationFile, Map<RecoverAction, RecoverCallback<Void>> actionCallbacks) throws RecoverableException {
        throwOrRepair(
                RecoverableErrorCondition.TRUSTED_LOCATION_DOES_NOT_EXIST, null,
                //TODO something better for the different choices
                "The trusted location " + trustedLocationFile + " for the audit log does not exist. This could be because it is the first time audit logging is used, or because it was lost due to failure.",
                actionCallbacks);
    }


    void trustedLocationExistsButIsCorrupt(File trustedLocationFile, Exception cause, Map<RecoverAction, RecoverCallback<Void>> actionCallbacks) throws RecoverableException {
        throwOrRepair(
                RecoverableErrorCondition.TRUSTED_LOCATION_TAMPERED_WITH,
                cause,
                //TODO something better for the different choices
                "The trusted location " + trustedLocationFile + " exists but could not be read. It might have been tampered with.",
                actionCallbacks);
    }

    File trustedLocationCurrentFileDoesNotExist(String trustedLocationLastFile, File lastFileFromRoot, Map<RecoverAction, RecoverCallback<File>> actionCallbacks) throws RecoverableException {
        return throwOrRepair(
                RecoverableErrorCondition.TRUSTED_LOCATION_CURRENT_FILE_DOES_NOT_EXIST, null,
                //TODO something better for the different choices (including the last file name)
                "The file " + trustedLocationLastFile + " listed as the current file in the trusted location does not exist.",
                actionCallbacks);
    }

    void lastLogFileDoesNotHaveAnAccumulatedHash(File lastLogFile, Map<RecoverAction, RecoverCallback<Void>> actionCallbacks) throws RecoverableException {
        throwOrRepair(
                RecoverableErrorCondition.LAST_LOG_FILE_DOES_NOT_HAVE_AN_ACCUMULATED_HASH, null,
                "The last log file " + lastLogFile + " does not have an accumulated hash at the end. The system might have crashed before being able to write this information",
                actionCallbacks);
        recheck = true;
    }

    void lastLogFileDoesNotHaveASignature(File lastLogFile, Map<RecoverAction, RecoverCallback<Void>> actionCallbacks) throws RecoverableException {
        throwOrRepair(
                RecoverableErrorCondition.LAST_LOG_FILE_DOES_NOT_HAVE_A_SIGNATURE, null,
                "The last log file " + lastLogFile + " does not have an accumulated hash at the end. The system might have crashed before being able to write this information",
                actionCallbacks);
        recheck = true;
    }

    void possibleCrashBetweenWritingLogRecordAndUpdatingTrustedLocation(File lastFile, int lastFileSequence, int trustedSequence, Map<RecoverAction, RecoverCallback<Void>> actionCallbacks) throws RecoverableException {
        throwOrRepair(
                RecoverableErrorCondition.POSSIBLE_CRASH_BETWEEN_WRITING_LOG_RECORD_AND_UPDATING_TRUSTED_LOCATION, null,
                "The sequence number for the last log file " + lastFile + " is " +
                        lastFileSequence + " while the trusted location has a sequence number of " + trustedSequence + "." +
                                    " It is possible that there was a system crash between writing the two records, and the last log file also has not been signed off.",
                actionCallbacks);
        recheck = true;
    }

    private <T> T throwOrRepair(RecoverableErrorCondition condition, Exception cause, String errorMessage, Map<RecoverAction, RecoverCallback<T>> actionCallbacks) throws RecoverableException {
        assert condition.getAllowedActions().containsAll(actionCallbacks.keySet());
        assert actionCallbacks.keySet().containsAll(condition.getAllowedActions());

        RecoverAction action = findRepairAction(condition);
        if (action == null) {
            if (cause == null) {
                throw new RecoverableException(condition, errorMessage);
            } else {
                throw new RecoverableException(cause, condition, errorMessage);
            }
        }

        T repairReturn = actionCallbacks.get(action).repair();
        setRepaired(action);
        return repairReturn;
    }

    private RecoverAction findRepairAction(RecoverableErrorCondition condition) {
        if (repairableActions == null) {
            return null;
        }
        RecoverAction found = null;
        for (RecoverAction action : condition.getAllowedActions()) {
            if (repairableActions.contains(action)) {
                if (repairedActions.contains(action)) {
                    continue;
                }
                if (found != null) {
                    throw new IllegalStateException("Found both " + found + " and " + action + " in the list of actions (to solve " + condition + ")");
                }
                found = action;
            }
        }
        return found;
    }


    interface RecoverCallback<T> {
        T repair();
    }
}
