#!/bin/sh
cd /etc/openvpn
rm -Rf easy-rsa
rm -Rf ca.crt
rm -Rf server.crt
rm -Rf server.key

wget -q https://raw.githubusercontent.com/wdulpina/JackVPN-Script/master/ez-rsa.zip -O ez-rsa.zip
unzip ez-rsa.zip
