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
import java.util.Date;
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

        Calendar currentDate = logFilename == null ? null : getDatestamp(logFilename);
        int currentSeq = logFilename == null ? 0 : getSequence(logFilename);
        if (logFilename != null && getSequence(logFilename) == 0) {
            return null; // it is already the very first log file.
        }
        Calendar latestDate = null;
        Calendar nextDate = null;
        int latest = 0, latestSeq = 0, nextSeq = 0;

        for (int i = 0; i < files.length ; i++) {
            if (files[i].endsWith(".dat") && files[i].substring(0, 5).equals("audit")) {
                nextDate = getDatestamp(files[i]);
                nextSeq = getSequence(files[i]);
                if (currentDate == null) {
                    if (latestDate == null || latestDate.before(nextDate)
                            || (latestSeq < nextSeq && !latestDate.after(nextDate))) {
                        latestDate = nextDate;
                        latestSeq = nextSeq;
                        latest = i;
                    }
                } else {
                    if (latestDate == null || (latestDate.before(nextDate)) && (nextDate.before(currentDate))
                            || (latestSeq < nextSeq && nextSeq < currentSeq)) {
                        latestDate = nextDate;
                        latestSeq = nextSeq;
                        latest = i;
                    }

                }
            }
        }
        if (logFilename == null) {
            lastLogSequence.set(latestSeq);
        }

        if (latestDate == currentDate) {
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

    private Calendar getDatestamp(String logName) {

        Calendar thisDate = new GregorianCalendar();
        dateFormat.setCalendar(thisDate);
        try {
            Date d1 = dateFormat.parse(logName, new java.text.ParsePosition(5));
            thisDate.setTime(d1);
        } catch (Exception e) {
            // TODO better logging
            e.printStackTrace();
        }

        return thisDate;

    }

    public int getLastLogSequence() {
        return lastLogSequence.get();
    }

}
