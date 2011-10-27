#!/bin/bash

sed -n 's/^ciphers\[[0-9]*\]\.value = htons(0x\(....\)) ; snprintf.* BUFFER_CIPHER_SUITES, "\([^"]*\)".*$/\1,\2/p' | \
    while IFS=, read k v; do echo "$(echo -n $k | tr 'A-F' 'a-f'),$v"; done