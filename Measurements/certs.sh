#!/usr/bin/env bash
# Build real DER X.509 hierarchies (root -> d-1 intermediates -> server/client leaves) for every
# signature algorithm and chain depth d = 1..4, with bank-like extensions on example domains.
set -euo pipefail
cd "$(dirname "$0")"
export LD_LIBRARY_PATH=$HOME/opt/openssl-3.5/lib
O=$HOME/opt/openssl-3.5/bin/openssl
mkdir -p certs
cat > certs/ext.cnf <<'CNF'
[req]
distinguished_name = dn
[dn]
[v3_root]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = 2.23.140.1.2.2,1.3.6.1.4.1.55555.1.1
crlDistributionPoints = URI:http://crl.pki.examplebank.example/root.crl
authorityInfoAccess = caIssuers;URI:http://pki.examplebank.example/root.crt
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth,clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:payments.examplebank.example,DNS:api.examplebank.example,DNS:swift-gw.examplebank.example
certificatePolicies = 2.23.140.1.2.2,1.3.6.1.4.1.55555.1.2
crlDistributionPoints = URI:http://crl.pki.examplebank.example/issuing.crl
authorityInfoAccess = OCSP;URI:http://ocsp.pki.examplebank.example,caIssuers;URI:http://pki.examplebank.example/issuing.crt
CNF
genkey() {   # alg out
  case $1 in
    RSA-2048) $O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $2 ;;
    RSA-3072) $O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out $2 ;;
    ECDSA-P256) $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $2 ;;
    *) $O genpkey -algorithm $1 -out $2 ;;
  esac
}
md() { case $1 in RSA-*|ECDSA-*) echo "-sha256" ;; *) echo "" ;; esac; }
DN="/C=VN/ST=Ha Noi/L=Ha Noi/O=Example Bank Joint Stock Company/OU=Payments PKI"
for alg in RSA-2048 RSA-3072 ECDSA-P256 ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f; do
  for d in 1 2 3 4; do
    D=certs/$alg/d$d; mkdir -p $D; cd $D
    genkey $alg root.key 2>/dev/null
    $O req -x509 -new -key root.key -subj "$DN/CN=Example Bank Root CA" -days 7300 $(md $alg) \
       -config ../../ext.cnf -extensions v3_root -out root.pem 2>/dev/null
    issuer=root; : > inter_chain.pem
    for i in $(seq 1 $((d - 1))); do
      genkey $alg ca$i.key 2>/dev/null
      $O req -new -key ca$i.key -subj "$DN/CN=Example Bank Issuing CA $i" -config ../../ext.cnf -out ca$i.csr 2>/dev/null
      $O x509 -req -in ca$i.csr -CA $issuer.pem -CAkey $issuer.key -CAcreateserial -days 3650 $(md $alg) \
         -extfile ../../ext.cnf -extensions v3_ca -out ca$i.pem 2>/dev/null
      cat ca$i.pem inter_chain.pem > tmp && mv tmp inter_chain.pem    # bottom-up order
      issuer=ca$i
    done
    for role in server client; do
      genkey $alg $role.key 2>/dev/null
      $O req -new -key $role.key -subj "$DN/CN=$role.payments.examplebank.example" -config ../../ext.cnf -out $role.csr 2>/dev/null
      $O x509 -req -in $role.csr -CA $issuer.pem -CAkey $issuer.key -CAcreateserial -days 397 $(md $alg) \
         -extfile ../../ext.cnf -extensions v3_leaf -out $role.pem 2>/dev/null
    done
    rm -f *.csr *.srl
    cd - >/dev/null
  done
  echo "certs: $alg done"
done
