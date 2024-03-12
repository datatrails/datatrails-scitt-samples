openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key private_key.pem -out certificate.csr
openssl x509 -signkey private_key.pem -in certificate.csr -req -days 365 -out certificate.pem
openssl smime -sign -in payload.txt -out payload.sig -outform DER -signer certificate.pem -inkey private_key.pem -nodetach
openssl base64 -in payload.sig -out payload_base64.sig


