#!/bin/sh
# Created by https://www.hostingtermurah.net
# Modified by 0123456

#Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
	apt-get -y install curl
fi
# initializing var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";

# go to root
cd

# install squid3
apt-get -y install squid
cat > /etc/squid/squid.conf <<-END
acl server dst x.x.x.x/32 localhost
acl checker src 188.93.95.137
acl ports_ port 22 53 21 8080 8000 3128 1194 443 80
acl CONNECT method CONNECT
http_port 3128
http_port 8080
http_port 8000
http_access allow server
http_access allow checker
#http_access deny !server
http_access deny !ports_
access_log none
netdb_filename none
cache_log /dev/null
forwarded_for off
via off
refresh_pattern . 0 0% 0
visible_hostname JustPlay
request_header_access Host allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access All deny all
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart

wget https://gitlab.com/azli5083/debian8/raw/master/googlecloud && bash googlecloud && rm googlecloud
