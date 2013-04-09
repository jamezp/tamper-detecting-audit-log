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


viewing certificate (test-viewing.cer)
======================================
$keytool  -genkeypair -alias audit-viewing -keyalg RSA -validity 365 -keystore test-viewing.keystore  -keysize 2048
Enter keystore password: changeit5
Re-enter new password: changeit5
....
Enter key password for <audit-sign>
   (RETURN if same as keystore password): changeit6  
Re-enter new password: changeit6

$keytool -export -alias audit-viewing -keystore test-viewing.keystore  -rfc -file test-viewing.cer
Enter keystore password:  changeit5
Certificate stored in file <test-viewing.cer>