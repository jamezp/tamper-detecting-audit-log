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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequenceGenerator;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class TrustedLocation {

    private final KeyManager keyManager;
    private final File trustedLocationFile;
    private final File logFileDir;
    private final File previousLogFile;
    private final int lastSequenceNumber;
    private final File currentInspectionLogFile;
    private final byte[] lastAccumulativeHash;

    private TrustedLocation(KeyManager keyManager, File logFileDir, File trustedLocationFile, File previousLogFile, File currentInspectionLogFile, int lastSequenceNumber, byte[] lastAccumulativeHash) {
        this.keyManager = keyManager;
        this.logFileDir = logFileDir;
        this.trustedLocationFile = trustedLocationFile;
        this.previousLogFile = previousLogFile;
        this.currentInspectionLogFile = currentInspectionLogFile;
        this.lastSequenceNumber = lastSequenceNumber;
        this.lastAccumulativeHash = lastAccumulativeHash;
    }


    static TrustedLocation create(KeyManager keyManager, File logFileDir, File trustedLocationFile) {
        final LogFileNameUtil logFileNameUtil = new LogFileNameUtil(logFileDir);
        File lastLogFile = logFileNameUtil.getPreviousLogFilename(null);
        File currentInspectionFile = null;
        byte[] lastAccumulativeHash = null;
        int lastSequenceNumber = 0;
        if (!trustedLocationFile.exists()) {
            if (lastLogFile != null) {
                //TODO be able to override this
                throw new IllegalStateException("The trusted location " + trustedLocationFile + " does not exist, and log files were found in " + logFileDir);
            }
        } else {
            Content content = new Content();
            int status = content.read(keyManager, trustedLocationFile);
            if (status == -1) {
                //TODO be able to override this
                throw new IllegalStateException("The trusted location " + trustedLocationFile + " is corrupt and may have been tampered with");
            }

            currentInspectionFile = new File(logFileDir, content.lastFileName);
            if (!currentInspectionFile.exists()) {
                //TODO be able to override this
                throw new IllegalStateException("Cannot find the current log file for verification " + currentInspectionFile);
            }
            lastAccumulativeHash = content.lastAccumulativeHash;
            lastSequenceNumber = content.lastSN;
        }

        TrustedLocation trustedLocation = new TrustedLocation(keyManager, logFileDir, trustedLocationFile, lastLogFile, currentInspectionFile, lastSequenceNumber, lastAccumulativeHash);
        return trustedLocation;
    }

    File getPreviousLogFile() {
        return previousLogFile;
    }

    File getCurrentInspectionLogFile() {
        return currentInspectionLogFile;
    }

    byte[] getAccumulatedMessageHash() {
        return lastAccumulativeHash;
    }


    int write(LogWriter logWriter) {
        byte [] fileBytes = null;
        byte [] asn1Block = generateASN1Block(logWriter);
        if (asn1Block == null) {
            throw new RuntimeException("Could not generate ASN1 block");
        }

        try{
              if (!trustedLocationFile.exists()) {
                  trustedLocationFile.createNewFile();
              }
              RandomAccessFile raf = new RandomAccessFile(trustedLocationFile, "rw");
              raf.setLength(0);
              try{
                  Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
                  cipher.init(Cipher.ENCRYPT_MODE, keyManager.getSecretKey(), keyManager.getPbeParameterSpec());
                  fileBytes = cipher.doFinal(asn1Block);
                  raf.write(fileBytes);
              } finally {
                  IoUtils.safeClose(raf);
              }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return 1;
    }

    private static class Content {
        private volatile String lastFileName;
        private volatile int lastSN;
        private volatile byte[] lastAccumulativeHash;

        private int read(KeyManager keyManager, File trustedLocation) {
            byte[] fileBytes = new byte[(int)trustedLocation.length()];
            if (trustedLocation.exists()) {
                byte[] decryptedBytes = null;
                try {
                    final RandomAccessFile raf = new RandomAccessFile(trustedLocation, "rw");
                    try {
                        raf.read(fileBytes);
                        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
                        cipher.init(Cipher.DECRYPT_MODE, keyManager.getSecretKey(), keyManager.getPbeParameterSpec());
                        decryptedBytes = cipher.doFinal(fileBytes);

                    } finally {
                        IoUtils.safeClose(raf);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                return extractASN1Block(decryptedBytes);
            }
            return 0;
        }

        private int extractASN1Block (byte[] asn1Block){
            ASN1InputStream aIn = new ASN1InputStream(asn1Block);
            try {
                ASN1Sequence sequence = (ASN1Sequence)aIn.readObject();

                lastFileName = ((DERIA5String)sequence.getObjectAt(0)).getString();
                lastSN = ((ASN1Integer)sequence.getObjectAt(1)).getValue().intValue();
                lastAccumulativeHash = ((DEROctetString)sequence.getObjectAt(2)).getOctets();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                IoUtils.safeClose(aIn);
            }
            return 0;
        }
    }

    private byte[] generateASN1Block(LogWriter logWriter){
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try {
            DERSequenceGenerator gen = new DERSequenceGenerator(bout);
            gen.addObject(new DERIA5String(logWriter.getLogFileName()));
            gen.addObject(new ASN1Integer(logWriter.getSequenceNumber()));
            gen.addObject(new DEROctetString(logWriter.getAccumulativeHash()));
            gen.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bout.toByteArray();
    }
}
