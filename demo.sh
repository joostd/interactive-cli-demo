#!/bin/bash

. ./util.sh
source ./demo.env

run 'clear'

desc "Get metadata from FIDO MDS"
run 'curl -L https://mds3.fidoalliance.org/ | less'
run 'curl -L https://mds3.fidoalliance.org/ --output md.jwt'

desc "The metadata is a Json Web Token (JWT)"
run 'cat md.jwt | step crypto jwt inspect --insecure | less'

desc "Step 1: Validate the JWT"

desc "Step 1a: Validate the JWT signing certificate"

desc "The JWT contains the certificate chain required for validation"
run 'cat md.jwt | step crypto jwt inspect --insecure | jq -r '.header.x5c''

desc "The MDS signing certificate is the first certificate"
run 'cat md.jwt | step crypto jwt inspect --insecure | jq -r '.header.x5c[0]''
desc "Decode to view its contents..."
run 'cat md.jwt | step crypto jwt inspect --insecure | jq -r '.header.x5c[0]' | base64 -d | openssl x509 -inform der -noout -text | less'
desc "or store it in a file..."
run 'cat md.jwt | step crypto jwt inspect --insecure | jq -r '.header.x5c[0]' | base64 -d | openssl x509 -inform der -out mds.pem'

desc "Extract the intermediate certificates"
run 'cat md.jwt | step crypto jwt inspect --insecure | jq -r '.header.x5c[1:][]' '
desc "... and save them in a file"
run 'cat md.jwt | step crypto jwt inspect --insecure | jq -r ".header.x5c[1:][]" | while read pem; do echo $pem | base64 -d | openssl x509 -inform der; done > intermediates.pem'

desc "Download the GlobalSign root certificate"
run 'wget http://secure.globalsign.com/cacert/root-r3.crt'
desc "Convert the root certificate from DER to PEM format"
run 'openssl x509 -inform der -in root-r3.crt -out root-r3.pem'

desc "We now have the complete CA chain"
run 'for file in root-r3.pem intermediates.pem mds.pem; do openssl x509 -noout -in $file -issuer -subject; done'

desc "Validate the MDS signing certificate against the CA path"
run 'openssl verify -CAfile root-r3.pem -untrusted intermediates.pem mds.pem'

desc "Finally, we can verify the JWT signature"
run 'cat md.jwt | step crypto jwt verify --key mds.pem --alg RS256 --subtle > md.jwt.json'

desc "Step 2: Extract information from the metadata"

desc "Extract the JWT payload"
run 'cat md.jwt.json | jq .payload > md.json'

desc "Extract the description of all metadata statements for keys with an AAGUID"
run 'cat md.json | jq -C | less -r'
run 'cat md.json | jq -r ".entries[] | select(.aaguid) | .metadataStatement | [.aaguid,.description]"'
run 'cat md.json | jq -r ".entries[] | select(.aaguid) | .metadataStatement | [.aaguid,.description] | @tsv"'
run 'cat md.json | jq -r ".entries[] | select(.aaguid) | .metadataStatement | [.aaguid,.description] | @tsv" > aaguid.tsv'

desc "Show all descriptions for YubiKeys"
run 'cat aaguid.tsv | sort -k2 | grep Yubi'
