#!/bin/bash

# config
CONFIG_BASE=/etc/ssl/openssl.cnf
KEY_SIZE=4096
CRL_DAYS=3650
CA_DAYS=3650
PASSFILE="passphrase"

# internal
CONFIG="-config openssl.cnf"
if [ ! -z "$PASSFILE" ]; then
  PASSIN="-passin file:$PASSFILE"
  PASSOUT="-passout file:$PASSFILE"
fi
CA="openssl ca $CONFIG $PASSIN -keyfile ca.key -cert ca.crt"

set -e

gen_crl() {
  echo Generating CRL
  $CA -gencrl -out crl.pem -crldays $CRL_DAYS
  return $?
}

usage() {
  echo >&2 "Usage: $0 newca | revoke <cert>"
  exit 1
}

case $1 in
  newca)
    if [ -f ca.crt ]; then
      echo >&2 Certificate already present. If you don\'t \
               want to proceed, press Ctrl+C now.
      read
    fi

    if [[ ! -z "$PASSFILE" && ! -f "$PASSFILE" ]]; then
      stty -echo
      read -p "Passphrase: " PW; echo
      stty echo
      echo "$PW" > "$PASSFILE"
    fi

    echo Setting up new CA
    if [ ! -f openssl.cnf ]; then
      sed 's/^dir.*/dir = ./' < "$CONFIG_BASE" > openssl.cnf
    fi

    echo Generating CA key
    openssl genrsa $PASSOUT -des3 -out ca.key $KEY_SIZE
    chmod 600 ca.key

    echo Generating CA certificate
    openssl req $CONFIG $PASSIN -new -key ca.key -x509 -days $CA_DAYS -out ca.crt

    echo Fingerprint: $(openssl x509 -fingerprint -noout -in ca.crt)

    touch index.txt
    echo 01 > crlnumber
    echo 01 > serial

    gen_crl
    ;;

  revoke)
    CERT="$2"
    [ -z "$CERT" ] && usage
    $CA -revoke $CERT
    gen_crl
    ;;

  *) usage;;
esac
