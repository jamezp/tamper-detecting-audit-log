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
import java.io.RandomAccessFile;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class PlayDetectFileSize {

    public static void main (String[] args) throws Exception {

//        final AtomicInteger count = new AtomicInteger();
//        final CyclicBarrier barrier = new CyclicBarrier(2);
//        final Object lock = new Object();
//
//        Runnable r = new Runnable() {
//            @Override
//            public void run() {
//                while (count < 10) {
//
//                    barrier.await();
//                }
//            }
//        };
//
//        for (int i = 0 ; i < 10 ; i++) {
//            barrier.await();
//        }

        File file = new File("/Users/kabir/temp/test.txt");
        file.createNewFile();

        long lastLen = file.length();
        RandomAccessFile raf = new RandomAccessFile(file, "rwd");
        for (int i = 0 ; ; i++) {
            long len = raf.length();
            if (file.length() != len) {
                System.out.println("Bad length " + file.length());
            }
            if (len != lastLen) {
                System.out.println("Bad length " + len);
            }
            raf.seek(len);
            raf.write(("Test" + i + "\n").getBytes());
            len = raf.length();
            lastLen = len;
            long x = len;
        }

    }

}
