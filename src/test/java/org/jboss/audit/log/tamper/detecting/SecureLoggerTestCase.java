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

import static junit.framework.Assert.assertNotNull;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;

import junit.framework.Assert;

import org.jboss.audit.log.AuditLogger;
import org.jboss.audit.log.LogFileNameUtil;
import org.jboss.audit.log.tamper.detecting.RecoverableErrorCondition.RecoverAction;
import org.jboss.audit.log.tamper.detecting.ServerKeyManager.EncryptingKeyPairInfo;
import org.jboss.audit.log.tamper.detecting.ServerKeyManager.SigningKeyPairInfo;
import org.jboss.audit.log.tamper.detecting.ServerKeyManager.ViewingCertificateInfo;
import org.junit.Before;
import org.junit.Test;

/**
 * Logging and verifying log files must be done on the server
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class SecureLoggerTestCase {

    File testLogDir;
    File trusted;

    @Before
    public void setupDirectories() {
        testLogDir = new File("target/test-logs");
        deleteDirectory(testLogDir);
        testLogDir.mkdirs();

        trusted = new File(testLogDir, "trusted");
        trusted.delete();
    }

    @Test
    public void testInitSigningKeyPair() throws Exception {
        getSigningKeyPair();
    }

    @Test
    public void testInitEncryptingKeyPair() throws Exception {
        getEncryptingKeyPair();
    }

    @Test
    public void testInitViewingCertificate() throws Exception {
        getViewingCertificate();
    }

    @Test
    public void testKeyManagerGetsInitialized() throws Exception {
        ServerKeyManager facade = new ServerKeyManager(getEncryptingKeyPair(), getSigningKeyPair(), getViewingCertificate());
        SecretKey key = facade.getSecretKey();
        Assert.assertNotNull(key);
        PBEParameterSpec pbeParameterSpec = facade.getPbeParameterSpec();
        Assert.assertNotNull(pbeParameterSpec);

        byte[] rawBytes = new byte[] {19, 30, -1, -113, 102, -15, -83, -89, -1, 46, 53, 7, -90, -123, 87, 23};
        Cipher cipher = Cipher.getInstance(facade.getEncryptingPublicKey().getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, facade.getEncryptingPublicKey());
        byte[] encryptedMessage = cipher.doFinal(rawBytes);
        Cipher cipher2 = Cipher.getInstance(facade.getEncryptingPrivateKey().getAlgorithm());
        cipher2.init(Cipher.DECRYPT_MODE, facade.getEncryptingPrivateKey());
        byte[] decrypted = cipher2.doFinal(encryptedMessage);

        Assert.assertTrue(Arrays.equals(rawBytes, decrypted));

    }

    @Test
    public void testCorruptTrustedLocation() throws Exception {
        trusted.createNewFile();
        try {
            createLogger();
            Assert.fail();
        } catch (RecoverableException expected) {
        }

        AuditLogger logger = createLogger(RecoverAction.REBUILD_TRUSTED_LOCATION);
        closeLog(logger);
    }

    @Test
    public void testMissingCurrentLogFile() throws Exception {
        AuditLogger logger = null;
        try {
            logger = createLogger();
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.CREATE_TRUSTED_LOCATION));
        }
        try {
            logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
            closeLog(logger);

            //First try deleting the only log file
            new LogFileNameUtil(testLogDir).findLatestLogFileName().delete();
            try {
                logger = createLogger();
                Assert.fail();
            } catch (RecoverableException expected) {
            }
            logger = createLogger(RecoverAction.INSPECT_LAST_LOG_FILE);
            closeLog(logger);

            //Now try with a few more and deleting the last
            logger = createLogger();
            logger.logMessage("aaaa".getBytes());
            closeLog(logger);
            logger = createLogger();
            logger.logMessage("aaaa".getBytes());
            logger.logMessage("aaaa".getBytes());
            logger.logMessage("aaaa".getBytes());
            closeLog(logger);

            new LogFileNameUtil(testLogDir).findLatestLogFileName().delete();
            try {
                logger = createLogger();
                Assert.fail();
            } catch (RecoverableException expected) {
            }
            logger = createLogger(RecoverAction.INSPECT_LAST_LOG_FILE);
            closeLog(logger);

            logger = createLogger();
        } finally {
            closeLog(logger);
        }
    }

    @Test
    public void testInitializeSecureLogger() throws Exception {
        AuditLogger logger = null;
        try {
            logger = createLogger();
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.CREATE_TRUSTED_LOCATION));
        }
        try {
            logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
            logger.logMessage("Hello".getBytes());
            closeLog(logger);

            logger = createLogger();
            logger.logMessage("Hello".getBytes());
            Thread.sleep(1500);
            logger.logMessage("Test".getBytes());

            closeLog(logger);

            logger = createLogger();
            logger.logMessage("Hello".getBytes());
        } finally {
            if (logger != null) {
                closeLog(logger);
            }
        }
    }

    @Test
    public void testCrashFullLogWrittenBeforeTrustedLocationWritten() throws Exception {
        //This tests recovery from a crash after the full log was written but before the trusted
        //location could be updated with the signature sequence number
        overrideTestDirAndTrusted("system-crash-logs/full-log-written-no-trustedlocation");
        AuditLogger logger = null;
        try {
            logger = createLogger();
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.REPAIR_TRUSTED_LOCATION));
        }
        logger = createLogger(RecoverAction.REPAIR_TRUSTED_LOCATION);
        closeLog(logger);
    }

    @Test
    public void testCrashBeforeSignature() throws Exception {
        //This tests recovery from a crash just before the final signature record was written.
        //The log file and the trusted location are in sync
        overrideTestDirAndTrusted("system-crash-logs/before-signature");
        AuditLogger logger = null;
        try {
            logger = createLogger();
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.REPAIR_MISSING_SIGNATURE));
        }
        logger = createLogger(RecoverAction.REPAIR_MISSING_SIGNATURE);
        closeLog(logger);
    }

    @Test
    public void testCrashBeforeSignatureBeforeTrustedLocationWritten() throws Exception {
        //This tests recovery from a crash just before the final signature record was written.
        //The last update to the trusted location did not happen
        overrideTestDirAndTrusted("system-crash-logs/before-signature-no-trustedlocation");
        AuditLogger logger = null;
        try {
            logger = createLogger();
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.REPAIR_TRUSTED_LOCATION));
        }
        try {
            logger = createLogger(RecoverAction.REPAIR_TRUSTED_LOCATION);
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.REPAIR_MISSING_SIGNATURE));
        }
        logger = createLogger(RecoverAction.REPAIR_MISSING_SIGNATURE);
        closeLog(logger);
    }

    @Test
    public void testCrashBeforeSignatureBeforeTrustedLocationWrittenAllInOne() throws Exception {
        //This tests recovery from a crash just before the final signature record was written.
        //The last update to the trusted location did not happen
        //Here we try to fix everything in one go
        overrideTestDirAndTrusted("system-crash-logs/before-signature-no-trustedlocation");
        AuditLogger logger = createLogger(RecoverAction.REPAIR_TRUSTED_LOCATION, RecoverAction.REPAIR_MISSING_SIGNATURE);
        closeLog(logger);
    }

    @Test
    public void testCrashDuringLogging() throws Exception {
        //This tests recovery from a crash before the final accumulated hash and signature records are written
        //The log file and the trusted location are in sync
        overrideTestDirAndTrusted("system-crash-logs/during-logging");
        AuditLogger logger = null;
        try {
            logger = createLogger();
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.REPAIR_MISSING_ACCUMULATED_HASH));
        }
        logger = createLogger(RecoverAction.REPAIR_MISSING_ACCUMULATED_HASH);
        closeLog(logger);
    }


    @Test
    public void testCrashDuringLoggingBeforeTrustedLocationWritten() throws Exception {
        //This tests recovery from a crash before the final accumulated hash and signature records are written
        //The last update to the trusted location did not happen
        overrideTestDirAndTrusted("system-crash-logs/during-logging-no-trustedlocation");
        AuditLogger logger = null;
        try {
            logger = createLogger();
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.REPAIR_TRUSTED_LOCATION));
        }

        try {
            logger = createLogger(RecoverAction.REPAIR_TRUSTED_LOCATION);
            Assert.fail("Should have failed");
        } catch (RecoverableException expected) {
            Assert.assertTrue(expected.getCondition().getAllowedActions().contains(RecoverAction.REPAIR_MISSING_ACCUMULATED_HASH));
        }
        logger = createLogger(RecoverAction.REPAIR_MISSING_ACCUMULATED_HASH);
        closeLog(logger);
    }

    @Test
    public void testCrashDuringLoggingBeforeTrustedLocationWrittenAllInOne() throws Exception {
        //This tests recovery from a crash just before the final signature record was written.
        //The last update to the trusted location did not happen
        //Here we try to fix everything in one go
        overrideTestDirAndTrusted("system-crash-logs/during-logging-no-trustedlocation");
        AuditLogger logger = createLogger(RecoverAction.REPAIR_TRUSTED_LOCATION, RecoverAction.REPAIR_MISSING_ACCUMULATED_HASH);
        closeLog(logger);
    }

//    @Test
//    public void testSetupLogForCrash() throws Exception {
//        //Just here to create a log in a debugger for use in the crashed tests
//        AuditLogger logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
//        logger.logMessage("Hello".getBytes());
//        logger.logMessage("Hello2".getBytes());
//        closeLog(logger);
//
//    }

    @Test
    public void testVerifyGoodLogFile() throws Exception {
        AuditLogger logger = null;
        try {
            logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
            logger.logMessage("Hello".getBytes());
            logger.logMessage("Hello again".getBytes());
        } finally {
            if (logger != null) {
                closeLog(logger);
            }
        }

        //File file = new LogFileNameUtil().getPreviousLogFilename(null);

        SecureAuditLoggerBuilder builder = createLogBuilder(false);
        builder.verifyLogFile(new SystemOutOutputStream(), LogRecordBodyOutputter.RAW, null);
    }

    @Test
    public void testVerifyLogFileChain() throws Exception {
        AuditLogger logger = null;
        try {
            logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
            logger.logMessage("Hello".getBytes());
            logger.logMessage("Hello again".getBytes());
        } finally {
            if (logger != null) {
                closeLog(logger);
            }
        }

        createLogBuilder(false).verifyLogFileChain(new SystemOutOutputStream(), LogRecordBodyOutputter.RAW, null, -1);

        try {
            Thread.sleep(1000); //TODO Sleep since the naming stuff needs 1s difference
            logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
            logger.logMessage("It is me".getBytes());
            logger.logMessage("Here I am".getBytes());
        } finally {
            if (logger != null) {
                closeLog(logger);
            }
        }

        createLogBuilder(false).verifyLogFileChain(new SystemOutOutputStream(), LogRecordBodyOutputter.RAW, null, -1);

        try {
            Thread.sleep(1000); //TODO Sleep since the naming stuff needs 1s difference
            logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
            logger.logMessage("It is me again".getBytes());
            logger.logMessage("Here I am again".getBytes());
        } finally {
            if (logger != null) {
                closeLog(logger);
            }
        }

        LogFileNameUtil util = new LogFileNameUtil(testLogDir);
        File currentFile = util.getPreviousLogFilename(null);
        System.out.println(currentFile);
        File file = util.getPreviousLogFilename(currentFile.getName());
        file.delete();

        createLogBuilder(false).verifyLogFileChain(new SystemOutOutputStream(), LogRecordBodyOutputter.RAW, null, -1);
    }

    @Test
    public void testViewLog() throws Exception {
        //The key thing here is that the viewer cannot verify the log file but it only needs the viewing p12 private key
        //matching the viewing certificate
        AuditLogger logger = null;
        try {
            logger = createLogger(RecoverAction.CREATE_TRUSTED_LOCATION);
            logger.logMessage("Hello".getBytes());
            logger.logMessage("Hello again".getBytes());
        } finally {
            if (logger != null) {
                closeLog(logger);
            }
        }

        LogViewer logViewer = LogViewer.create(getResourceFile("viewing-key.p12"), "changeit5c", "changeit6", testLogDir);
        logViewer.viewLogFile(new SystemOutOutputStream(), LogRecordBodyOutputter.RAW, null);
    }

    @Test
    public void testViewLogEncrypted() throws Exception {
        //The key thing here is that the viewer cannot verify the log file but it only needs the viewing p12 private key
        //matching the viewing certificate
        SecureAuditLoggerBuilder builder = createLogBuilder(true, RecoverAction.CREATE_TRUSTED_LOCATION);
        AuditLogger logger = builder.buildLogger();
        try {
            logger.logMessage("Hello".getBytes());
            logger.logMessage("Hello again".getBytes());
        } finally {
            if (logger != null) {
                closeLog(logger);
            }
        }

        LogViewer logViewer = LogViewer.create(getResourceFile("viewing-key.p12"), "changeit5c", "changeit6", testLogDir);
        logViewer.viewLogFile(new SystemOutOutputStream(), LogRecordBodyOutputter.RAW, null);
    }


    private void overrideTestDirAndTrusted(String logDir) throws IOException, URISyntaxException {
        File fromDir = new File("src");
        fromDir = new File(fromDir, "test");
        fromDir = new File(fromDir, "resources");
        fromDir = new File(fromDir, logDir.replace('/', File.separatorChar));
        Assert.assertTrue(fromDir.exists());
        Assert.assertTrue(fromDir.isDirectory());

        for (File file : fromDir.listFiles()) {
            final File tgt = new File(testLogDir, file.getName());
            tgt.delete();
            InputStream in = new BufferedInputStream(new FileInputStream(file));
            try {
                OutputStream out = new BufferedOutputStream(new FileOutputStream(tgt));
                try {
                    byte[] bytes = new byte[1024];
                    int i = in.read(bytes);
                    while (i != -1) {
                        out.write(bytes, 0, i);
                        i = in.read(bytes);
                    }
                } finally {
                    IoUtils.safeClose(out);
                }
            } finally {
                IoUtils.safeClose(in);
            }
        }
        trusted = new File(testLogDir, "trusted");
        Assert.assertTrue(trusted.exists());
    }

    private AuditLogger createLogger(RecoverAction...recoverActions) throws KeyStoreInitializationException, RecoverableException, IOException, URISyntaxException, ValidationException {
        SecureAuditLoggerBuilder builder = createLogBuilder(false, recoverActions);
        return builder.buildLogger();
    }

    private SecureAuditLoggerBuilder createLogBuilder(boolean encrypted, RecoverAction...recoverActions) throws KeyStoreInitializationException, RecoverableException, IOException, URISyntaxException, ValidationException {
        SecureAuditLoggerBuilder builder = SecureAuditLoggerBuilder.createBuilder(testLogDir)
                .signingStoreBuilder()
                    .setPath(getResourceFile("test-sign.keystore"))
                    .setKeyName("audit-sign")
                    .setStorePassword("changeit1")
                    .setKeyPassword("changeit2")
                    .setHashAlgorithm(HashAlgorithm.SHA1)
                    .done()
                .encryptingStoreBuilder()
                    .setPath(getResourceFile("test-encrypt.keystore"))
                    .setKeyName("audit-encrypt")
                    .setStorePassword("changeit3")
                    .setKeyPassword("changeit4")
                    .done()
                .setViewingCertificatePath(getResourceFile("viewing-cert.cer"))
                .setTrustedLocation(trusted);

        if (encrypted) {
            builder.setEncryptLogMessages();
        }


        for (RecoverAction repairAction : recoverActions) {
            builder.addRecoverAction(repairAction);
        }
        return builder;
    }

    private SigningKeyPairInfo getSigningKeyPair() throws IOException, URISyntaxException, KeyStoreInitializationException {
        File file = getResourceFile("test-sign.keystore");
        SigningKeyPairInfo wrapper = SigningKeyPairInfo.create(file, "changeit1", "changeit2", "audit-sign", HashAlgorithm.SHA1);
        Assert.assertNotNull(wrapper);
        return wrapper;
    }

    private EncryptingKeyPairInfo getEncryptingKeyPair() throws IOException, URISyntaxException, KeyStoreInitializationException {
        File file = getResourceFile("test-encrypt.keystore");
        EncryptingKeyPairInfo wrapper = EncryptingKeyPairInfo.create(file, "changeit3", "changeit4", "audit-encrypt");
        Assert.assertNotNull(wrapper);
        return wrapper;
    }

    private ViewingCertificateInfo getViewingCertificate() throws IOException, URISyntaxException, KeyStoreInitializationException {
        File file = getResourceFile("viewing-cert.cer");
        ViewingCertificateInfo wrapper = ViewingCertificateInfo.create(file);
        Assert.assertNotNull(wrapper);
        return wrapper;
    }

    private File getResourceFile(String name) throws IOException, URISyntaxException {
        URL url = getClass().getResource(name);
        assertNotNull(url);
        File file =  new File(url.toURI());
        assertNotNull(file);
        return file;
    }

    private void deleteDirectory(File file) {
        if (!file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            for (File child : file.listFiles()) {
                deleteDirectory(child);
            }
        } else {
            file.delete();
        }
    }

    private void closeLog(AuditLogger logger) throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(1);
        logger.closeLog(new AuditLogger.ClosedCallback() {

            @Override
            public void closed() {
                latch.countDown();
            }
        });
        latch.await();
    }

    private static class SystemOutOutputStream extends OutputStream {

        @Override
        public void write(int b) throws IOException {
            System.out.write(b);
            System.out.flush();
        }
    }
}
