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
package org.jboss.audit.util;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;

import javax.xml.bind.DatatypeConverter;

import org.jboss.audit.log.tamper.detecting.IoUtils;

/**
 * <p>On my system the syslog output looks something like this:</p>
 * <pre>
 * Apr 26 10:54:48 1 2013-04-26T10[4294967295] <Info>: 54:48.690+01:00 - java 1851 - - 48656C6C6F2066726F6D204B6162697220467269204170722032362031303A35343A34382042535420323031330A20746869732069732061206E6577206C696E65
 *</pre>
 * <p> Regexp to get the hex encoded encoded part:</p>
 * <pre>
 * $echo Apr 26 10:54:48 1 2013-04-26T10[4294967295] Info: 54:48.690+01:00 - java 1851 - - 48656C6C6F2066726F6D204B6162697220467269204170722032362031303A35343A34382042535420323031330A20746869732069732061206E6577206C696E65 | sed 's/.* - - \([A-Z,0-9]*\)/\1/'
 * 48656C6C6F2066726F6D204B6162697220467269204170722032362031303A35343A34382042535420323031330A20746869732069732061206E6577206C696E65
 * </pre>
 * <p>Get the encoded parts of the records:</p>
 * <pre>
 * $syslog | grep " java " | sed 's/.* - - \([A-Z,0-9]*\)/\1/'
 * </pre>
 * <p>Get the encoded parts of the records into a file:</p>
 * <pre>
 * $syslog | grep " java " | sed 's/.* - - \([A-Z,0-9]*\)/\1/' > /some/where/tmp.txt
 * </pre>
 * <p>Then you can run this util to extract the log records:</p>
 * <pre>java --classpath <path to this jar> org.jboss.audit.util.SyslogHexDecoder /some/where/tmp.txt /some/where/output.txt</pre>
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class SyslogHexDecoder {

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage SyslogDecoder <file to decode> <output file>");
            return;
        }
        final File encrypted = new File(args[0]);
        final File output = new File(args[1]);

        if (!encrypted.exists()) {
            System.out.println("Input file " + encrypted + " does not exist");
        }
        if (output.exists()) {
            output.delete();
        }
        System.out.println("Decoding " + encrypted.getAbsolutePath() + " to " + output.getAbsolutePath());

        final BufferedReader in = new BufferedReader(new FileReader(encrypted));
        try {
            final OutputStream out = new BufferedOutputStream(new FileOutputStream(output));
            try {
                String encoded = in.readLine();
                while (encoded != null) {
                    try {
                        byte[] bytes = DatatypeConverter.parseHexBinary(encoded);
                        out.write(bytes);
                    } catch(IllegalArgumentException e) {
                        //I have some stuff in my local syslog that was not encoded
                        System.err.println("'" + encoded + "' does not appear to be a hex string");
                    }
                    encoded = in.readLine();
                }
            } finally {
                IoUtils.safeClose(out);
            }
        } finally {
            IoUtils.safeClose(in);
        }
    }
}
