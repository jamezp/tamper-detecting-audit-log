*** To enable basic encrypted communication ***
===============================================

Followed the instructions at http://emo.sourceforge.net/cert-login-howto.html while logged in as root to
1) Set up the ca certificate and private key
2) Set up the server's certificate and key
3) Add the following to server's /etc/rsyslog.conf. Putting the pem files anywhere else, caused big problems with the text 
'rsyslogd-2068: could not load module '/lib64/rsyslog/lmnsd_gtls.so', rsyslog error -2078' which mean there are permission
problems reading the certificates/keys.

   # Provides TLS syslog reception
   $ModLoad imtcp #Load tcp driver
   $DefaultNetstreamDriver gtls # Sets the gtls driver as the default
   # Certificates
   $DefaultNetstreamDriverCAFile /etc/pki/rsyslog/ca.pem
   $DefaultNetstreamDriverCertFile /etc/pki/rsyslog/server-cert.pem
   $DefaultNetstreamDriverKeyFile /etc/pki/rsyslog/server-key.pem
   # run driver in TLS-only mode
   $InputTCPServerStreamDriverMode 1
   # To not authenticate the client use 'anon', to authenticate the client use 'x509/certvalid'
   $InputTCPServerStreamDriverAuthMode anon  
   $InputTCPServerRun 514 # start up listener at port 514
4) Copy the ca.pem to the client and import it to a truststore using keytool, using 'changeit' as the trust store password
   $keytool -import -alias ca -file server/ca.pem -keystore cacerts

*** Then to enable client authentication checking for certificate validity ***
==============================================================================
1) Create a machine certificate and private key, signing the certificate off with the server's ca.
2) Create a keystore on the client 
   $openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem -out client.p12 -name syslog-client
   (you should enter a password according to the google gods)
   $keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore client.keystore -srckeystore client.p12 -srcstoretype PKCS12 -srcstorepass test -alias syslog-client
3) Change $InputTCPServerStreamDriverAuthMode from 'anon' to either 'x509/certvalid' (to just check that the client has a cert) or 'x509/name' (to check allowed names,
   in which case I think you need $InputTCPServerStreamDriverPermittedPeer entries)
