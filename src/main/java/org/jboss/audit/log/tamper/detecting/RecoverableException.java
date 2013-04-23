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

import org.jboss.audit.log.tamper.detecting.RecoverableErrorCondition.RecoverAction;


/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class RecoverableException extends Exception {
    private static final long serialVersionUID = 1L;

    final RecoverableErrorCondition condition;

    public RecoverableException(RecoverableErrorCondition condition, String message) {
        super(appendActions(condition, message));
        this.condition = condition;
    }

    public RecoverableException(Exception cause, RecoverableErrorCondition condition, String message) {
        super(appendActions(condition, message), cause);
        this.condition = condition;

    }

    private static String appendActions(RecoverableErrorCondition condition, String message) {
        //TODO Make the action output a bit more informative
        StringBuilder sb = new StringBuilder(message);
        boolean first = true;
        for (RecoverAction action : condition.getAllowedActions()) {
            if (first) {
                sb.append("\nAvailable actions are to: ");
                first = false;
            } else {
                sb.append(", ");
            }
            sb.append(action);
        }
        return sb.toString();
    }


    RecoverableErrorCondition getCondition() {
        return condition;
    }
}
