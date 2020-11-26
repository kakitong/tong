#!/bin/bash

# Installing dependencies
apt-get update
apt-get -y install build-essential g++ # libltdl-dev
# aptitude update
# aptitude build-dep squid3

cd /root
echo "Downloading Squid source code ..."
wget --quiet "http://www.squid-cache.org/Versions/v3/3.5/squid-3.5.7.tar.gz"
echo "Extracting Squid source code ..."
tar -xzf squid-3.5.7.tar.gz
rm "squid-3.5.7.tar.gz"
cd squid-3.5.7

echo "Configuring Squid source code ..."
./configure --quiet --sysconfdir=/etc/squid --prefix=/opt/squid
echo "Compiling Squid source code ..."
make -j4 > log-file 2>&1
echo "Installing Squid ..."
make install > log-file 2>&1
cd /root
rm -rf squid-3.5.7

mv /etc/squid/squid.conf /etc/squid/squid.conf.def
echo "Downloading Squid configuration file ..."
wget -q -O /etc/squid/squid.conf "https://raw.githubusercontent.com/kakitong/tong/main/z/squid.conf"
chmod 644 /etc/squid/squid.conf

chmod 777 /opt/squid/var/cache/squid
chmod 777 /opt/squid/var/logs/
echo "Running Squid ... "
/opt/squid/sbin/squid
