#! /bin/bash
#
# Simple script to generate a certificate and sign against snakeoil
#

set -e

KEY_FILE=server.key
REQ_FILE=server.req
CERT_FILE=server.pem

CA_CERT=../snakeoil.pem
CA_KEY=../snakeoil.key

openssl genrsa -out ${KEY_FILE}

openssl req                 \
	-new                \
	-out ${REQ_FILE}    \
	-outform pem        \
	-key ${KEY_FILE}    \
	-config req.conf    \
	-reqexts req

openssl x509               \
	-in ${REQ_FILE}    \
	-req               \
	-set_serial 2345   \
	-CA ${CA_CERT}     \
	-CAkey ${CA_KEY}   \
	-extfile cert.conf \
	-extensions cert   \
	-out ${CERT_FILE}
