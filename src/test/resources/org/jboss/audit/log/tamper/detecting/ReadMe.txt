The keystores were created as follows:

signing key store (test-sign.keystore)
======================================
$keytool -genkeypair -alias audit-sign -keyalg RSA -validity 365 -keystore test-sign.keystore
Enter keystore password: changeit1 
Re-enter new password: changeit1
....
Enter key password for <audit-sign>
   (RETURN if same as keystore password): changeit2  
Re-enter new password: changeit2

encrypting key store (test-encrypt.keystore)
============================================
$keytool  -genkeypair -alias audit-encrypt -keyalg RSA -validity 365 -keystore test-encrypt.keystore 
Enter keystore password: changeit3 
Re-enter new password: changeit3
....
Enter key password for <audit-sign>
   (RETURN if same as keystore password): changeit4  
Re-enter new password: changeit4


viewing certificate and private key (viewing-cert.cer and viewing-key.p12) 
======================================

$openssl genrsa -out viewing-key.key 2048

$openssl req -new -key viewing-key.key -out viewing-key.csr 
....
A challenge password []:changeit5

$openssl x509 -req -days 3600 -in viewing-key.csr -signkey viewing-key.key -out viewing-cert.cer
$openssl pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -export -in viewing-cert.cer -inkey viewing-key.key -out viewing-key.p12 -name "Test Key"
Enter Export Password: changeit6
Verifying - Enter Export Password: changeit6

$rm viewing-key.key 
$rm viewing-key.csr 

