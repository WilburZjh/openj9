echo "start running script";

echo "[ req ]
prompt                 = no
days                   = 365
distinguished_name     = req_distinguished_name
attributes             = my_req_attributes
req_extensions         = v3_req

[ req_distinguished_name ]
countryName            = AB
stateOrProvinceName    = CD
localityName           = EFG_HIJ
organizationName       = MyOrg
organizationalUnitName = MyOrgUnit
commonName             = mycommname.com
emailAddress           = emailaddress@myemail.com

[my_req_attributes]
challengePassword      = changeit

[ v3_req ]
basicConstraints       = CA:false
extendedKeyUsage       = serverAuth
subjectAltName         = @sans

[ sans ]
DNS.0 = localhost
DNS.1 = myexampleserver.com" >> openssl_csr.conf;

echo "[evp_sect]
 # This will have no effect as FIPS mode is off by default.
 # Set to yes to enter FIPS mode, if supported
 fips_mode = yes
" >> /etc/pki/tls/openssl.cnf

# generate rsa private in pkcs8 standard and public key
openssl genpkey -algorithm RSA -out rsaprivate.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rsaprivate.pem -out rsapublic.pem
openssl pkcs8 -topk8 -in rsaprivate.pem -nocrypt -out rsaprivatepkcs8.pem -v2 aes-256-cbc

# create a self-signed X.509 certificate based on RSA private key
openssl req -new -out tmprsa.csr -key rsaprivatepkcs8.pem -config openssl_csr.conf
openssl x509 -req -days 365 -in tmprsa.csr -signkey rsaprivatepkcs8.pem -out rsatest.cer

# Convert the x.509 cert and key to a pkcs12 file
openssl pkcs12 -export -in rsatest.cer -inkey rsaprivatepkcs8.pem -out testKSRSA.p12 -certpbe AES-256-CBC -keypbe AES-256-CBC -nomac -password pass:changeit
rm -rf rsaprivate.pem rsapublic.pem rsaprivatepkcs8.pem tmprsa.csr rsatest.cer

# generate ec private in pkcs8 standard and public key
# openssl ecparam -list_curves
openssl ecparam -name prime256v1 -genkey -out ecprivate.pem
openssl ec -in ecprivate.pem -pubout -out ecpublic.pem
openssl pkcs8 -topk8 -in ecprivate.pem -nocrypt -out ecprivatepkcs8.pem

# create a self-signed X.509 certificate based on EC private key
openssl req -new -out tmpec.csr -key ecprivatepkcs8.pem -config openssl_csr.conf
openssl x509 -req -days 365 -in tmpec.csr -signkey ecprivatepkcs8.pem -out ectest.cer

# Convert the x.509 cert and key to a pkcs12 file
openssl pkcs12 -export -in ectest.cer -inkey ecprivatepkcs8.pem -out testKSEC.p12 -certpbe AES-256-CBC -keypbe AES-256-CBC -nomac -password pass:changeit
rm -rf ecprivate.pem ecpublic.pem ecprivatepkcs8.pem tmpec.csr openssl_csr.conf ectest.cer

echo "Finish creating certificates, keys and keystores";
# the expected arguments are:
# $1 is the TEST_ROOT
# $2 is the JAVA_COMMAND
# $3 is the JVM_OPTIONS
# $4 is the MAINCLASS_KEY_EXTRACT_IMPORT
# $5 is the APP ARGS
$2 $3 -cp $1/fips.jar $4 $5;
rm -rf testKSRSA.p12 testKSEC.p12