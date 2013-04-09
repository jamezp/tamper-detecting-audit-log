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

import java.io.File;
import java.net.URL;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;

import junit.framework.Assert;

import org.jboss.audit.log.tamper.detecting.KeyManager.EncryptingKeyPairInfo;
import org.jboss.audit.log.tamper.detecting.KeyManager.SigningKeyPairInfo;
import org.jboss.audit.log.tamper.detecting.KeyManager.ViewingCertificateInfo;
import org.junit.Test;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public class KeyStoreTestCase {

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
        KeyManager facade = new KeyManager(getEncryptingKeyPair(), getSigningKeyPair(), getViewingCertificate());
        SecretKey key = facade.getSecretKey();
        Assert.assertNotNull(key);
        PBEParameterSpec pbeParameterSpec = facade.getPbeParameterSpec();
        Assert.assertNotNull(pbeParameterSpec);
    }

    @Test
    public void testInitializeSecureLogger() throws Exception {
        File file = new File("target/test-logs");
        deleteDirectory(file);
        file.mkdirs();

        SecureLoggerBuilder builder = SecureLoggerBuilder.Factory.createBuilder();
        SecureLogger logger = builder
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
            .setViewingCertificatePath(getResourceFile("test-viewing.cer"))
            .setLogFileRoot(file)
            .buildLogger();

            logger.logMessage("Hello".getBytes());

    }

    private SigningKeyPairInfo getSigningKeyPair() throws Exception {
        File file = getResourceFile("test-sign.keystore");
        SigningKeyPairInfo wrapper = SigningKeyPairInfo.create(file, "changeit1", "changeit2", "audit-sign", HashAlgorithm.SHA1);
        Assert.assertNotNull(wrapper);
        return wrapper;
    }

    private EncryptingKeyPairInfo getEncryptingKeyPair() throws Exception {
        File file = getResourceFile("test-encrypt.keystore");
        EncryptingKeyPairInfo wrapper = EncryptingKeyPairInfo.create(file, "changeit3", "changeit4", "audit-encrypt");
        Assert.assertNotNull(wrapper);
        return wrapper;
    }

    private ViewingCertificateInfo getViewingCertificate() throws Exception {
        File file = getResourceFile("test-viewing.cer");
        ViewingCertificateInfo wrapper = ViewingCertificateInfo.create(file);
        Assert.assertNotNull(wrapper);
        return wrapper;
    }

    private File getResourceFile(String name) throws Exception {
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
}
