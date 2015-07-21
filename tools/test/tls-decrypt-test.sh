#!/bin/sh

../parsifal --pcap-tcp 8080 -T tls https.pcap | diff -qs - tcp-raw-records.txt
../parsifal --pcap-tcp 8080 -T tls https.pcap --always-enrich | diff -qs - tcp-records.txt

../parsifal -p 8080 -T pcap-tls https.pcap --always-enrich | diff -qs - pcap-encrypted-tls-records.txt
../parsifal -p 8080 -T pcap-tls https.pcap --keylogfile https-secrets.txt --always-enrich | diff -qs - pcap-tls-records.txt

../parsifal --pcap-tls 8080 https.pcap --keylogfile https-secrets.txt --always-enrich -T string | diff -qs - tls-records.txt
