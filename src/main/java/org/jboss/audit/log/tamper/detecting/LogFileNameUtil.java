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
import java.io.FilenameFilter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class LogFileNameUtil {
    private static final Pattern PATTERN = Pattern.compile("audit.*-.*-.*.dat");

    private final static AtomicInteger lastLogSequence = new AtomicInteger(-1);
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH_mm_ssz", Locale.UK);
    private final File logFileDir;

    /** Creates a new instance of LogFilenameClass */
    LogFileNameUtil(File logFileDir) {
        this.logFileDir = logFileDir;
    }

    File generateNewLogFileName() {
        Calendar today = new GregorianCalendar(TimeZone.getTimeZone("GMT+1"));
        StringBuffer tmp = dateFormat.format(today.getTime(), new StringBuffer(), new java.text.FieldPosition(0));
        int last = lastLogSequence.incrementAndGet();
        String newFileName = "audit" + tmp + last + ".dat";
        return new File(logFileDir, newFileName);
    }

    File getPreviousLogFilename(String logFilename) {
        String[] files = logFileDir.list(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return PATTERN.matcher(name).matches();
            }
        });
        if (files.length == 0) {
            return null;
        }

        String currentDate = logFilename == null ? null : getDatestamp(logFilename);
        int currentSeq = logFilename == null ? 0 : getSequence(logFilename);
        if (logFilename != null && getSequence(logFilename) == 0) {
            return null;
        }
        String latestDate = null;
        String nextDate = null;
        int latest = 0, latestSeq = 0, nextSeq = 0;

        for (int i = 0; i < files.length ; i++) {
            nextDate = getDatestamp(files[i]);
            nextSeq = getSequence(files[i]);
            if (currentDate == null) {
                if (latestDate == null || latestDate.compareTo(nextDate) < 0
                        || (latestSeq < nextSeq && latestDate.compareTo(nextDate) >= 0)) {
                    latestDate = nextDate;
                    latestSeq = nextSeq;
                    latest = i;
                }
            } else {
                if (latestDate == null || (latestDate.compareTo(nextDate) < 0) && (nextDate.compareTo(currentDate) < 0)
                        || (latestSeq < nextSeq && nextSeq < currentSeq)) {
                    latestDate = nextDate;
                    latestSeq = nextSeq;
                    latest = i;
                }

            }
        }
        if (logFilename == null) {
            lastLogSequence.set(latestSeq);
        }

        if (latestDate.equals(currentDate)) {
            return null;
        }
        return new File(logFileDir, files[latest]);

    }

    private int getSequence(String fileName) {
        String sequenceStr = fileName.substring(27, fileName.indexOf('.'));
        return Integer.parseInt(sequenceStr);
    }

    File findLatestLogFileName() {
        return getPreviousLogFilename(null);
    }

    private String getDatestamp(String logName) {
        return logName.substring(5, 27);
    }

    public int getLastLogSequence() {
        return lastLogSequence.get();
    }

}
