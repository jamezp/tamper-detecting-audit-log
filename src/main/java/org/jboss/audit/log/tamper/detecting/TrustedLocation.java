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
import java.util.Arrays;
import java.util.Collections;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.jboss.audit.log.tamper.detecting.LogReader.LogInfo;
import org.jboss.audit.log.tamper.detecting.RecoverableErrorCondition.RecoverAction;
import org.jboss.audit.log.tamper.detecting.RecoverableErrorContext.RecoverCallback;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class TrustedLocation {

    private final KeyManager keyManager;
    private final File trustedLocationFile;
    private final File previousLogFile;
    private final File currentInspectionLogFile;
    private final byte[] lastAccumulativeHash;
    private final int lastSequenceNumber;
    private final boolean inspectingPreviousLogFile;

    private TrustedLocation(KeyManager keyManager, File logFileDir, File trustedLocationFile, File previousLogFile, File currentInspectionLogFile,
            int lastSequenceNumber, byte[] lastAccumulativeHash, boolean inspectingPreviousLogFile) {
        this.keyManager = keyManager;
        this.trustedLocationFile = trustedLocationFile;
        this.previousLogFile = previousLogFile;
        this.currentInspectionLogFile = currentInspectionLogFile;
        this.lastAccumulativeHash = lastAccumulativeHash;
        this.lastSequenceNumber = lastSequenceNumber;
        this.inspectingPreviousLogFile = inspectingPreviousLogFile;
    }


    static TrustedLocation create(final RecoverableErrorContext recoverableContext, final KeyManager keyManager, final File logFileDir, final File trustedLocationFile) throws RecoverableException {
        final LogFileNameUtil logFileNameUtil = new LogFileNameUtil(logFileDir);
        final File lastLogFile = logFileNameUtil.getPreviousLogFilename(null);
        File currentInspectionFile = null;
        byte[] lastAccumulativeHash = null;
        int lastSequenceNumber = 0;
        boolean inspectingPreviousLogFile = false;
        if (!trustedLocationFile.exists()) {
            recoverableContext.trustedLocationDoesNotExistWhileLogFilesExist(
                    trustedLocationFile,
                    Collections.singletonMap(RecoverAction.CREATE_TRUSTED_LOCATION, RecreateTrustedLocationCallback.create(trustedLocationFile)));
        } else {
            Content content = null;
            try {
                content = Content.read(keyManager, trustedLocationFile);
            } catch (Exception e) {
                recoverableContext.trustedLocationExistsButIsCorrupt(
                        trustedLocationFile,
                        e,
                        Collections.singletonMap(RecoverAction.REBUILD_TRUSTED_LOCATION, RecreateTrustedLocationCallback.create(trustedLocationFile)));
            }

            if (content != null) {
                currentInspectionFile = new File(logFileDir, content.lastFileName);
                if (!currentInspectionFile.exists()) {
                    currentInspectionFile = recoverableContext.trustedLocationCurrentFileDoesNotExist(
                            currentInspectionFile.getName(),
                            lastLogFile,
                            Collections.singletonMap(RecoverAction.INSPECT_LAST_LOG_FILE, (RecoverCallback<File>)new RecoverCallback<File>() {
                                @Override
                                public File repair() {
                                    return lastLogFile;
                                }
                            }));
                    inspectingPreviousLogFile = true;
                }
                lastAccumulativeHash = content.lastAccumulativeHash;
                lastSequenceNumber = content.lastSequenceNumber;
            }
        }

        TrustedLocation trustedLocation = new TrustedLocation(keyManager, logFileDir, trustedLocationFile, lastLogFile, currentInspectionFile, lastSequenceNumber, lastAccumulativeHash, inspectingPreviousLogFile);
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

    int write(File logFile, int sequenceNumber, byte[] accumulatedHash) {
        byte [] fileBytes = null;
        byte [] asn1Block = generateASN1Block(logFile.getName(), sequenceNumber, accumulatedHash);
        if (asn1Block == null) {
            throw new RuntimeException("Could not generate ASN1 block when writing trusted location");
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

    void checkLastLogRecord(final RecoverableErrorContext recoverableContext, final LogInfo lastLogInfo) throws RecoverableException, ValidationException {
        if (currentInspectionLogFile != null && !inspectingPreviousLogFile) {
            if (lastLogInfo.getLastSequenceNumber() != lastSequenceNumber) {
                if (lastLogInfo.getLastSequenceNumber() == lastSequenceNumber + 1) {
                    recoverableContext.possibleCrashBetweenWritingLogRecordAndUpdatingTrustedLocation(
                            lastLogInfo.getLogFile(),
                            lastLogInfo.getLastSequenceNumber(),
                            lastSequenceNumber,
                            Collections.singletonMap(RecoverAction.REPAIR_TRUSTED_LOCATION, (RecoverCallback<Void>)new RecoverCallback<Void>() {
                                @Override
                                public Void repair() {
                                    write(currentInspectionLogFile, lastLogInfo.getLastSequenceNumber(), lastLogInfo.getAccumulativeDigest().getAccumulativeHash());
                                    return null;
                                }
                            }));
                    return;
                } else {
                    throw new ValidationException("The sequence number in " + currentInspectionLogFile + " was " + lastLogInfo.getLastSequenceNumber() + " but the trusted location has this as " + this.lastSequenceNumber);
                }
            } else if (lastLogInfo.getAccumulatedHash() != null && !Arrays.equals(lastLogInfo.getAccumulatedHash(), this.lastAccumulativeHash)) {
                throw new ValidationException("The accumulated hash is different in " + currentInspectionLogFile + " and in the trusted location");
            }

            if (lastLogInfo.getAccumulatedHash() == null) {
                recoverableContext.lastLogFileDoesNotHaveAnAccumulatedHash(
                        lastLogInfo.getLogFile(),
                        Collections.singletonMap(RecoverAction.REPAIR_MISSING_ACCUMULATED_HASH, (RecoverCallback<Void>)new RecoverCallback<Void>() {
                            @Override
                            public Void repair() {
                                try {
                                    LogWriter.createForFixing(keyManager, lastLogInfo.getLogFile(), TrustedLocation.this, lastLogInfo.getAccumulativeDigest(),
                                            lastSequenceNumber, lastLogInfo.getLastRecordLength())
                                            .writeMissingAccumulatedHashAndSignatureRecordsAndCloseWriter();
                                } catch (IOException e) {
                                    throw new RuntimeException(e);
                                }
                                return null;
                            }
                        }));
            } else if (lastLogInfo.getSignature() == null) {
                recoverableContext.lastLogFileDoesNotHaveASignature(
                        lastLogInfo.getLogFile(),
                        Collections.singletonMap(RecoverAction.REPAIR_MISSING_SIGNATURE, (RecoverCallback<Void>)new RecoverCallback<Void>() {
                            @Override
                            public Void repair() {
                                try {
                                    LogWriter.createForFixing(keyManager, lastLogInfo.getLogFile(), TrustedLocation.this, lastLogInfo.getAccumulativeDigest(),
                                            lastSequenceNumber, lastLogInfo.getLastRecordLength())
                                            .writeMissingSignatureRecordAndCloseWriter();
                                } catch (IOException e) {
                                    throw new RuntimeException(e);
                                }
                                return null;
                            }
                        }));
                return;
            }
        }
    }


    private byte[] generateASN1Block(String logFileName, int sequenceNumber, byte[] accumulatedHash){
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try {
            DERSequenceGenerator gen = new DERSequenceGenerator(bout);
            gen.addObject(new DERIA5String(logFileName));
            gen.addObject(new ASN1Integer(sequenceNumber));
            gen.addObject(new DEROctetString(accumulatedHash));
            gen.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return bout.toByteArray();
    }

    static class Content {
        private volatile String lastFileName;
        private volatile int lastSequenceNumber;
        private volatile byte[] lastAccumulativeHash;

        private Content (String lastFileName, int lastSequenceNumber, byte[] lastAccumulativeHash) {
            this.lastFileName = lastFileName;
            this.lastSequenceNumber = lastSequenceNumber;
            this.lastAccumulativeHash = lastAccumulativeHash;
        }

        private static Content read(KeyManager keyManager, File trustedLocationFile) throws Exception {
            byte[] fileBytes = new byte[(int)trustedLocationFile.length()];
            byte[] decryptedBytes = null;
            final RandomAccessFile raf = new RandomAccessFile(trustedLocationFile, "rw");
            try {
                raf.read(fileBytes);
                Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
                cipher.init(Cipher.DECRYPT_MODE, keyManager.getSecretKey(), keyManager.getPbeParameterSpec());
                decryptedBytes = cipher.doFinal(fileBytes);
                return extractASN1Block(decryptedBytes);
            } finally {
                IoUtils.safeClose(raf);
            }
        }

        private static Content extractASN1Block (byte[] asn1Block) throws Exception {
            ASN1InputStream aIn = new ASN1InputStream(asn1Block);
            try {
                ASN1Sequence sequence = (ASN1Sequence)aIn.readObject();
                String lastFileName = ((DERIA5String)sequence.getObjectAt(0)).getString();
                int lastSequenceNumber = ((ASN1Integer)sequence.getObjectAt(1)).getValue().intValue();
                byte[] lastAccumulativeHash = ((DEROctetString)sequence.getObjectAt(2)).getOctets();

                return new Content(lastFileName, lastSequenceNumber, lastAccumulativeHash);
            } finally {
                IoUtils.safeClose(aIn);
            }
        }
    }

    private static class RecreateTrustedLocationCallback implements RecoverCallback<Void>{

        private final File trustedLocationFile;

        private RecreateTrustedLocationCallback(final File trustedLocationFile) {
            this.trustedLocationFile = trustedLocationFile;
        }

        static RecoverCallback<Void> create(final File trustedLocationFile){
            return new RecreateTrustedLocationCallback(trustedLocationFile);
        }

        @Override
        public Void repair() {
            boolean created = false;
            try {
                trustedLocationFile.delete();
                created = trustedLocationFile.createNewFile();
                if (!created) {
                    created = trustedLocationFile.exists();
                }
            } catch (IOException e) {
            }
            if (!created) {
                throw new IllegalStateException("Failed to create " + trustedLocationFile);
            }
            return null;
        }

    }
}
