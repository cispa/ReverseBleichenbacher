#/usr/bin/env bash

# clone tls-lite-ng
git clone https://github.com/tlsfuzzer/tlslite-ng.git tlslite-ng-bleichenbacher

# checkout correct commit
cd tlslite-ng-bleichenbacher
git checkout 6805bcb8e6afb0d22b2f5b24e97ba21c525d4d69

# apply patche to integrate our attack
git apply ../tlslite-ng-bleichenbacher.patch

# add the index.html to the server
cp ../index.html .
