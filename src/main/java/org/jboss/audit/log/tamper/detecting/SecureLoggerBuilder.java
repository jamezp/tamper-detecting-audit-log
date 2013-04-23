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
import java.io.OutputStream;
import java.util.List;

import org.jboss.audit.log.tamper.detecting.RecoverableErrorCondition.RecoverAction;

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public interface SecureLoggerBuilder {

    /**
     * Get the builder for the keystore information for the key pair used to encrypt/decrypt
     * the secure random number, and the encrypted log records
     *
     * @return the builder
     */
    EncryptingKeyPairBuilder encryptingStoreBuilder();

    /**
     * Get the builder for the keystore information for the key pair used to sign the
     * log record
     *
     * @return the builder
     */
    SigningKeyPairBuilder signingStoreBuilder();

    /**
     * Set the path for the certificate to view the log
     *
     * @param path the path of the viewing certificate
     * @return this builder
     */
    SecureLoggerBuilder setViewingCertificatePath(File path) throws KeyStoreInitializationException ;

    /**
     * Set the root directory for the log files
     *
     * @param file the log file root directory
     * @return this builder
     */
    SecureLoggerBuilder setLogFileRoot(File file);

    /**
     * Set the trusted location maintaing the last log file, accumulated hash and sequence number
     *
     * @param file the trusted location path
     * @return this builder
     */
    SecureLoggerBuilder setTrustedLocation(File file);

    /**
     * Add a recover action to recover from a {@link RecoverableException} when calling {@link #buildLogger()}
     *
     * @return this builder
     */
    SecureLoggerBuilder addRecoverAction(RecoverAction recoverAction);

    /**
     * If called the logger will encrypt the user log messages
     *
     * @return this builder
     */
    SecureLoggerBuilder setEncryptLogMessages();

    /**
     * Builds the logger
     *
     * @return a secure logger
     * @throws KeyStoreInitializationException if there was a problem loading any of the keystores and certificates
     * @throws RecoverableException if there were some problems relating the current log to the trusted location
     * @throws ValidationException if there were some problems checking the log
     */
    SecureLogger buildLogger() throws KeyStoreInitializationException, RecoverableException, ValidationException;

    /**
     * Lists the log files in the log file root
     *
     * @return the list of the log files sorted from newest to oldest
     */
    List<File> listLogFiles();

    /**
     * Verify/read a single log file.
     *
     * @param outputStream the output stream to write the output to
     * @param bodyOutputter interprets the body bytes for each log record. If {@code null} the body will not be interpreted
     * @param file the file to inspect. If {@code null} it will inspect the most recent file in the log file root directory
     *
     */
    void verifyLogFile(OutputStream outputStream, LogRecordBodyOutputter bodyOutputter, File file) throws KeyStoreInitializationException;

    /**
     * Verify/read a chain of log files.
     *
     * @param outputStream the output stream to write the output to
     * @param bodyOutputter interprets the body bytes for each log record. If {@code null} the body will not be interpreted
     * @param file the file to inspect. If {@code null} it will inspect the most recent file in the log file root directory
     * @param count the number of older files to inspect. {@code 0} means only inspect the current, and {@code -1} means inspect all the way to the end.
     */
    void verifyLogFileChain(OutputStream outputStream, LogRecordBodyOutputter bodyOutputter, File file, int count) throws KeyStoreInitializationException;

    interface SigningKeyPairBuilder {
        SigningKeyPairBuilder setPath(File location);
        SigningKeyPairBuilder setStorePassword(String password);
        SigningKeyPairBuilder setKeyPassword(String password);
        SigningKeyPairBuilder setKeyName(String name);
        SigningKeyPairBuilder setHashAlgorithm(HashAlgorithm algorithm);
        SecureLoggerBuilder done();

    }

    interface EncryptingKeyPairBuilder {
        EncryptingKeyPairBuilder setPath(File location);
        EncryptingKeyPairBuilder setStorePassword(String password);
        EncryptingKeyPairBuilder setKeyPassword(String password);
        SigningKeyPairBuilder setKeyName(String name);
        SecureLoggerBuilder done();
    }

    class Factory {
        public static SecureLoggerBuilder createBuilder() {
            return new SecureLoggerBuilderImpl();
        }
    }
}
