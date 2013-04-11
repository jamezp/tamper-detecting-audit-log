package org.jboss.audit.log.tamper.detecting;

public interface SecureLogger {

    void logMessage(byte[] message);
    void closeLog();
}
