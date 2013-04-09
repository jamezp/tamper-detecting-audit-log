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

/**
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public interface SecureLoggerBuilder {

    EncryptingKeyPairBuilder encryptingStoreBuilder();

    SigningKeyPairBuilder signingStoreBuilder();

    SecureLoggerBuilder setViewingCertificatePath(File path) throws KeyStoreInitializationException ;

    SecureLoggerBuilder setLogFileRoot(File file);

    SecureLogger buildLogger() throws KeyStoreInitializationException;

    SecureLogReader buildReader() throws KeyStoreInitializationException;

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
