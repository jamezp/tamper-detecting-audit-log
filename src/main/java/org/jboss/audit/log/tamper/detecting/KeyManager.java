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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
class KeyManager {
    private final EncryptingKeyPairInfo encryptingKeyPair;
    private final SigningKeyPairInfo signingKeyPair;
    private final ViewingCertificateInfo viewingCertificate;
    private final SecretKey secretKey;
    private final PBEParameterSpec pbeParameterSpec;

    KeyManager(EncryptingKeyPairInfo encryptingKeyStore, SigningKeyPairInfo signingKeyStore, ViewingCertificateInfo viewingKeyStore) throws KeyStoreInitializationException {
        this.encryptingKeyPair = encryptingKeyStore;
        this.signingKeyPair = signingKeyStore;
        this.viewingCertificate = viewingKeyStore;
        PBEKeySpec keySpec = new PBEKeySpec(signingKeyStore.storePassword.toCharArray());
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            this.secretKey = factory.generateSecret(keySpec);
        } catch (Exception e) {
            throw new KeyStoreInitializationException(e);
        }
        byte[] salt = { (byte) 0x11, (byte) 0x23, (byte) 0x53, (byte) 0x65,
                (byte) 0xbc, (byte) 0xef, (byte) 0xf1, (byte) 0x34 };
        pbeParameterSpec = new PBEParameterSpec(salt, 10);
    }

    PublicKey getViewingPublicKey() {
        return viewingCertificate.publicKey;
    }

    PublicKey getEncryptingPublicKey() {
        return encryptingKeyPair.publicKey;
    }

    String getSigningAlgorithmName() {
        return signingKeyPair.algorithmName;
    }

    PrivateKey getSigningPrivateKey() {
        return signingKeyPair.privateKey;
    }

    byte[] getSigningPublicKeyCert() {
        return signingKeyPair.publicKeyCert;
    }

    SecretKey getSecretKey() {
        return secretKey;
    }

    HashAlgorithm getHashAlgorithm() {
        return signingKeyPair.hashAlgorithm;
    }

    PBEParameterSpec getPbeParameterSpec() {
        return pbeParameterSpec;
    }

    static class SigningKeyPairInfo {
        private final String storePassword;
        private final PublicKey publicKey;
        private final PrivateKey privateKey;
        private final Certificate certificate;
        private final byte[] publicKeyCert;
        private final HashAlgorithm hashAlgorithm;
        private final String algorithmName;

        private SigningKeyPairInfo(String storePassword, PrivateKey privateKey, Certificate certificate, byte[] publicKeyCert,
                PublicKey publicKey, HashAlgorithm hashAlgorithm, String algorithmName) {
            this.storePassword = storePassword;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.certificate = certificate;
            this.publicKeyCert = publicKeyCert;
            this.hashAlgorithm = hashAlgorithm;
            this.algorithmName = algorithmName;
        }

        static SigningKeyPairInfo create(final File keyStoreLocation, final String keyStorePassword,
                final String keyPassword, String keyName, HashAlgorithm algorithm) throws KeyStoreInitializationException {

            assert keyStoreLocation != null : "keyStoreLocation is null";
            assert keyStoreLocation.exists() : keyStoreLocation + " does not exist";
            assert keyStorePassword != null : "keyStorePassword is null";
            assert keyPassword != null : "keyPassword is null";
            assert keyName != null : "keyName is null";
            assert algorithm != null : "algorithm is null";

            try {
                final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(new BufferedInputStream(new FileInputStream(keyStoreLocation)), keyStorePassword.toCharArray());
                final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, keyPassword.toCharArray());
                final Certificate certificate = keyStore.getCertificate(keyName);
                final byte[] publicKeyCert = certificate.getEncoded();
                final PublicKey publicKey = certificate.getPublicKey();
                final String algorithmName = algorithm.toString() + "with" + publicKey.getAlgorithm();
                return new SigningKeyPairInfo(keyStorePassword, privateKey, certificate, publicKeyCert, publicKey, algorithm, algorithmName);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new KeyStoreInitializationException(e);
            }
        }
    }

    static class EncryptingKeyPairInfo {
        private final PublicKey publicKey;
        private final String storePassword;
        private final PrivateKey privateKey;

        private EncryptingKeyPairInfo(String storePassword, PrivateKey privateKey, PublicKey publicKey) {
            this.storePassword = storePassword;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        static EncryptingKeyPairInfo create(final File keyStoreLocation, final String keyStorePassword, final String keyPassword, String keyName) throws KeyStoreInitializationException {
            assert keyStoreLocation != null : "keyStoreLocation is null";
            assert keyStoreLocation.exists() : keyStoreLocation + " does not exist";
            assert keyStorePassword != null : "keyStorePassword is null";
            assert keyPassword != null : "keyPassword is null";
            assert keyName != null : "keyName is null";

            try {
                final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(new BufferedInputStream(new FileInputStream(keyStoreLocation)), keyStorePassword.toCharArray());
                final PrivateKey privateKey = (PrivateKey)keyStore.getKey(keyName, keyPassword.toCharArray());
                final Certificate certificate = keyStore.getCertificate(keyName);
                final PublicKey publicKey = certificate.getPublicKey();
                return new EncryptingKeyPairInfo(keyStorePassword, privateKey, publicKey);
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException)e;
                }
                throw new KeyStoreInitializationException(e);
            }
        }
    }

    static class ViewingCertificateInfo {
        private final PublicKey publicKey;

        public ViewingCertificateInfo(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        static ViewingCertificateInfo create(File viewingPublicKeyFile) throws KeyStoreInitializationException {
            assert viewingPublicKeyFile != null : "viewingPublicKeyFile is null";
            final InputStream in;
            try {
                 in = new FileInputStream(viewingPublicKeyFile);
            } catch (IOException e) {
                throw new KeyStoreInitializationException(e);
            }
            try{
                java.security.cert.CertificateFactory cf = null;
                cf = java.security.cert.CertificateFactory.getInstance("X.509");
                java.security.cert.Certificate cert = cf.generateCertificate(in);
                return new ViewingCertificateInfo(cert.getPublicKey());
            } catch (Exception e) {
                if (e instanceof RuntimeException) {
                    throw (RuntimeException)e;
                }
                throw new KeyStoreInitializationException(e);
            }
        }
    }
}
