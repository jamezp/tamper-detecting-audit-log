The .pem files in the server/ directory come from the rsyslog distribution and are used as an example. They must be copied across to the server with permissions 400.
Then the servers /etc/rsyslog.conf must be modified to use them and set up tls, e.g.

-----
# Provides TLS syslog reception
$ModLoad imtcp
$DefaultNetstreamDriver gtls # Sets the gtls driver as the default
# Certificates
$DefaultNetstreamDriverCAFile /root/rsyslog-tls-certificates/ca.pem
$DefaultNetstreamDriverCertFile /root/rsyslog-tls-certificates/cert.pem
$DefaultNetstreamDriverKeyFile /root/rsyslog-tls-certificates/key.pem
$InputTCPServerStreamDriverMode 1 # run driver in TLS-only mode
# Use 'x509/name' to authenticate the certificate name, 'x509/certvalid' to check the client has a valid certificate, 
# 'anon' to allow anonymous non-authenticated clients
$InputTCPServerStreamDriverAuthMode anon 
$InputTCPServerRun 10514 # start up listener at port 10514
-----
cacerts is used as the client's truststore and was created by
$keytool -import -alias ca -file server/ca.pem -keystore cacerts
'changeit' is the trust store password

---- 
Create the client certificates as shown in http://www.rsyslog.com/doc/tls_cert_machine.html and http://www.sebdangerfield.me.uk/2011/12/setting-up-a-centralised-syslog-server-in-the-cloud/
I called them syslog-client-cert.pem and syslog-client-key.key.

Import the client certificate into the client keystore
$ keytool -import -v -file syslog-client-cert.pem -keystore client-keystore.jks
'changeit' is the keystore password

TODO:
Then I followed the instructions at http://emo.sourceforge.net/cert-login-howto.html to import them into a keystore which is used by the client.
Note that the original ca.pem used for DefaultNetstreamDriverCAFile must be used to sign the client certificate
  



These contain some good info on all this:
http://www.sebdangerfield.me.uk/2011/12/setting-up-a-centralised-syslog-server-in-the-cloud/ 
http://www.rsyslog.com/doc/rsyslog_secure_tls.html

 
