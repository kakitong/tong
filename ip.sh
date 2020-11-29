#!/bin/bash
# Created By M Fauzan Romandhoni (+6281311310405) (m.fauzan58@yahoo.com)

clear

#Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
	apt-get -y install curl
fi

if [[ $USER != "root" ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

# get the VPS IP
#ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`

#MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [ "$ether" = "" ]; then
        ether=eth0
fi

# MULAI SETUP
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;
if [ $USER != 'root' ]; then
echo "Sorry, for run the script please using root user"
exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
echo "Sorry, you need to run this as root"
exit 2
fi
MyScriptName='Sshinjector'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='143'

# Your SSH Banner
SSH_Banner='https://raw.githubusercontent.com/0879168516/DBuster/master/banner'

# Dropbear Ports
Dropbear_Port1='777'
Dropbear_Port2='442'

# Stunnel Ports
Stunnel_Port1='447' # through Dropbear
Stunnel_Port2='444' # through OpenSSH

# OpenVPN Ports
OpenVPN_TCP_Port='443'
OpenVPN_UDP_Port='1194'

# Privoxy Ports
Privoxy_Port1='3356'
Privoxy_Port2='8086'

# OpenVPN Config Download Port
OvpnDownload_Port='81' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Jakarta'
#############################


#############################
#############################
## All function used for this script
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw firewalld -y

 
 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 
 # Now installing all our wanted services
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq fail2ban -y

 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
 
 # Installing OpenVPN by pulling its repository inside sources.list file 
 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
 apt-get update
 apt-get install openvpn -y
}

function InstWebmin(){
 # Download the webmin .deb package
 # You may change its webmin version depends on the link you've loaded in this variable(.deb file only, do not load .zip or .tar.gz file):
  WebminFile='http://prdownloads.sourceforge.net/webadmin/webmin_1.920_all.deb'
 wget -qO webmin.deb "$WebminFile"
 
 # Installing .deb package for webmin
 dpkg --install webmin.deb
 
 rm -rf webmin.deb
 
 # Configuring webmin server config to use only http instead of https
 sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf
 
 # Then restart to take effect
 systemctl restart webmin
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=ID/ST=Jateng/L=Blora/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0
[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c
[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c
MyStunnelC

cat > /etc/stunnel/stunnel.pem <<END
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1seWBRJU8s9I3To26Fk/UYcoBO4fOQbHY/i+O+nn150tue6o
NmFPp4717TBDMz/9D+o49NY2mS/LE8EGpMj0kv6QbwLDWSUHYH3TvUmQXhUnOiEB
nYyPDpc/l3XJx329mOXlPzabm1uJaIx4wGtZuSkjtpcY5kDPYedsUz4HLLclHoIZ
3E75OMuzpaXudnNhH7wUTYo1afP7Njoh8wp6/PPDHhsvCvjnXMptOdPQz/Nwa9gc
11i27k20vcSplk5fVxXlKsa4NpVfYGD8CzcBF5roSBzr3UN2NyDb6RJvcXwW7suO
KdNY3AAJQABr7lioQIqSmRpiUluduj/rE28awwIDAQABAoIBAQCR84j/o0h0w+V4
6FFdrSA5D8ZjK0muX+vpBKSJZFb3D0l+ey513cTaUWzPJKfV0NrwELNptZPenzq6
Dsar/h8tMK4HsfH7xwzvRjI4BCCFvowslTdaz6R7Ps6o5xMabFkF6NvTDBHMDfUf
Ra3c3FZZXBp3vs/d0BbdKf1Tx+fqOr+wnk5nPuM2U8NvgWkc7Rb5OupSH9pIwMCB
Fdc/WOCnt2pbOXsF9sX3cO4OanF4bSxvSe7F6vVw/ScqMo0v+503Sq0apmkE5fk7
KoNtlNAKb3XExm6PhjYsjfZje8KDzPvaEwgD8lQqa+yg89GiBe9UhcctsK1ImJA5
4ulEmaWZAoGBAPKJfykiBx5y8uOd2rO7uc+Wc3OYiytAN4GNHxOXgE6no5UnlhQM
a2uAEy5Q58pG07Yvxo+IVGigJ4yg0Xq3xjQVOzT78mshY78NoM/VpoyYHilxzVyG
tiIaGDUGGzyVSJj38ZguWVeKKPB0RfpEaRzYcibsv8iyMbUMVcRir39NAoGBAOKz
pl6qjrSRiCpedjEB0YuRVPpISJwUcEk0FH7Q5WSK10IVhAGPtai1hkpbw58YkCFb
NHYC/0wL5wFPZI3qBKQpWZRTKUkjP5r4hXHcVoUvENxEXFA9SK2yMgFik6ZbdyJX
i0WkaTmqdI82FJ6pjZYA+2NBTHKt7oY8wkHTPRpPAoGAcuPpRc3lu2nOXz6WrE+A
HLLza83WFx3rbUYxc3FwCVJmLjC7ajHb7OeVrnoK4wocHhCRqcp12b4MHhTMRqqp
jGCGVHoJAvClNIq7I9jcdXtVxmIvWuZBfvQHhY6n9lHtOvExE9rY3ZwH+qfJwl0H
we9SW9gInYS0AUSfmFD7O30CgYBTWfoxlEQj395Qtap/GkwRJL45x5nqyRj/0UY3
2lZ9QQ8kHQUMDeqcvSFC9bpXJJDZss73FOMI8tdcg/RUuVY7hXiKMIlderhIIlfu
JTUqgsOQORI37lBqjLoWCEiBQd/roIR0dp65tRJmFVw/ede072d+duPExm6MrIo/
6YrtwQKBgB5yowpjTSrl9MzqdjePTgVg5eu0GFABtFsG4GlxH9ZcL5odAC4NWNjg
FG+ktJEASIjzUKJPxbvfr/hhA66Z6vYusPqxU25Zzfo1++iahiw5e/iYekUTzgrt
MNdI7jzHENNJiEnoi+HGD7pc8BhdZre3ccJfvhPoecWhpqjN6Iva
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEQjCCAyqgAwIBAgIJAI5V9N6sws3WMA0GCSqGSIb3DQEBCwUAMIG1MQswCQYD
VQQGEwJJRDEUMBIGA1UECAwLSmF3YSBUZW5nYWgxDjAMBgNVBAcMBUJsb3JhMRgw
FgYDVQQKDA9Tc2hpbmplY3Rvci5uZXQxKTAnBgNVBAsMIEZyZWUgUHJlbWl1bSBT
U0ggYW5kIFZQTiBTZXJ2aWNlMRgwFgYDVQQDDA9Tc2hpbmplY3Rvci5uZXQxITAf
BgkqhkiG9w0BCQEWEmNzQHNzaGluamVjdG9yLm5ldDAeFw0yMDA2MTExNjQ3Mjda
Fw0yMzA2MTExNjQ3MjdaMIG1MQswCQYDVQQGEwJJRDEUMBIGA1UECAwLSmF3YSBU
ZW5nYWgxDjAMBgNVBAcMBUJsb3JhMRgwFgYDVQQKDA9Tc2hpbmplY3Rvci5uZXQx
KTAnBgNVBAsMIEZyZWUgUHJlbWl1bSBTU0ggYW5kIFZQTiBTZXJ2aWNlMRgwFgYD
VQQDDA9Tc2hpbmplY3Rvci5uZXQxITAfBgkqhkiG9w0BCQEWEmNzQHNzaGluamVj
dG9yLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANbHlgUSVPLP
SN06NuhZP1GHKATuHzkGx2P4vjvp59edLbnuqDZhT6eO9e0wQzM//Q/qOPTWNpkv
yxPBBqTI9JL+kG8Cw1klB2B9071JkF4VJzohAZ2Mjw6XP5d1ycd9vZjl5T82m5tb
iWiMeMBrWbkpI7aXGOZAz2HnbFM+Byy3JR6CGdxO+TjLs6Wl7nZzYR+8FE2KNWnz
+zY6IfMKevzzwx4bLwr451zKbTnT0M/zcGvYHNdYtu5NtL3EqZZOX1cV5SrGuDaV
X2Bg/As3ARea6Egc691Ddjcg2+kSb3F8Fu7LjinTWNwACUAAa+5YqECKkpkaYlJb
nbo/6xNvGsMCAwEAAaNTMFEwHQYDVR0OBBYEFHNxhRdYKxujZ8kHgL5pyakgfBVB
MB8GA1UdIwQYMBaAFHNxhRdYKxujZ8kHgL5pyakgfBVBMA8GA1UdEwEB/wQFMAMB
Af8wDQYJKoZIhvcNAQELBQADggEBACa2jAmN4jFeX5KVO6V5gGO0+Y4tcc+7fMMg
Tfffk1Mmx77S6nY4RCeIpBezV8J1eDWPdn/+lL8l1y80/JqI7cTAgDCI1cphy9aN
vfHWDlbffvxWOkaQ+HsQ8h+SlHy8Q4hmXBG13rZt+6vzJY9MpNquAscP3N/dY0+L
ADgmaSfpoS3vH6thiOMDEaKoBdi+MP/xHcn1fCqgrNwd/6N9rYThNIRsvWE4qPxg
2wYSJcnV02pNQ1NW9jvOUQkXLSGgEGUBZHl0Q2r/RNu8UCeMXZ9iRvNlEM4YsMBV
/H/KdydZN7YWcviNC3QKjfELdIdbgcU86fOx7psq1x8UmkQp2mA=
-----END CERTIFICATE-----
END

 # setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf

 # Restarting stunnel service
 systemctl restart $StunnelDir

}

function InsOpenVPN(){
 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf' > /etc/openvpn/server_tcp.conf
# OpenVPN TCP
port OVPNTCP
proto tcp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.200.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log tcp.log
verb 2
ncp-disable
cipher none
auth none
myOpenVPNconf

cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN UDP
port OVPNUDP
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
verify-client-cert none
username-as-common-name
key-direction 0
plugin /etc/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log udp.log
verb 2
ncp-disable
cipher none
auth none
myOpenVPNconf2

 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIFZDCCBEygAwIBAgIJANDo1Jr6Al+yMA0GCSqGSIb3DQEBCwUAMIHRMQswCQYD
VQQGEwJJRDEUMBIGA1UECBMLSmF3YSBUZW5nYWgxDjAMBgNVBAcTBUJsb3JhMRgw
FgYDVQQKEw9Tc2hpbmplY3Rvci5uZXQxMTAvBgNVBAsTKEZyZWUgUHJlbWl1bSBT
U0ggZGFuIFZQTiBTU0wvVExTIFNlcnZpY2UxGzAZBgNVBAMTElNzaGluamVjdG9y
Lm5ldCBDQTEPMA0GA1UEKRMGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJjc0Bzc2hp
bmplY3Rvci5uZXQwHhcNMjAwNjExMDQwNjEyWhcNMzAwNjA5MDQwNjEyWjCB0TEL
MAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4wDAYDVQQHEwVCbG9y
YTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQLEyhGcmVlIFByZW1p
dW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYDVQQDExJTc2hpbmpl
Y3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3DQEJARYSY3NA
c3NoaW5qZWN0b3IubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0K3vlvCxz3Rsx5y0SX90erEgCzFvpRJfQasAZaWKtnq/jbNt0ofIyY6l12yko6Ri
jvjljPcIUvfqWtwlNYTfP3I/UHO2Kd2635cGN6KMvLNsMsSqfFPndBl/okn/8ewD
6zmNFZ5H4FVXqB6YNZ6NYW2UTwzsxJjPsFVhiT/kzZ4dDB1m1gFSVC//NfWUZuvk
PuPet7rKHKwe6blrCcU0J+JhHLwSavZ6TNMVDAEBBqkk6cqEEcZ7GiW0sDfqEfkT
NsJh3WpllTIeqUokfh68oJVoLxI1RPPOdYONGNMVf/uPiNHLRi4S2Q+nVG4ePKdn
3s04NAVXCZF8KQ4MHH3C2wIDAQABo4IBOzCCATcwHQYDVR0OBBYEFMMZw/FDwT+3
l99B42dj1oUOXvbcMIIBBgYDVR0jBIH+MIH7gBTDGcPxQ8E/t5ffQeNnY9aFDl72
3KGB16SB1DCB0TELMAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4w
DAYDVQQHEwVCbG9yYTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQL
EyhGcmVlIFByZW1pdW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYD
VQQDExJTc2hpbmplY3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqG
SIb3DQEJARYSY3NAc3NoaW5qZWN0b3IubmV0ggkA0OjUmvoCX7IwDAYDVR0TBAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAinNNz43TcTf8ffvjJ1aKEQScaSuBXIT+
9C8PLXWOhOZIFDxAAA40HtZu8iCjtpCu0Z+rLxDqnu2+KSgiOZXxp4mS3ooa6j5B
ImeGIclzRgKPsSHZHU8VXXYdnPZP6KeBPWYnwc8bz9exG36Hpe9UBmvuWPtIAh2l
8eFNzTiOoJwdPP3HpELYoB70ES8F4LtoIVteaZCoDubay0HT36SFGg1sUQ+6DqYl
aRKiEUEkLjQAwe5Js8LtJTPWtrOpJvstmPJvCP38ycVIUBK/xrQl+PDKWE+7o2lA
9cS9EcGkLyGX1pKYWFiNbNKxgMWp34MmM9axxYwANj08l1ZEqVtEvw==
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=ID, ST=Jawa Tengah, L=Blora, O=Sshinjector.net, OU=Free Premium SSH dan VPN SSL/TLS Service, CN=Sshinjector.net CA/name=server/emailAddress=cs@sshinjector.net
        Validity
            Not Before: Jun 11 04:06:12 2020 GMT
            Not After : Jun  9 04:06:12 2030 GMT
        Subject: C=ID, ST=Jawa Tengah, L=Blora, O=Sshinjector.net, OU=Free Premium SSH dan VPN SSL/TLS Service, CN=server/name=server/emailAddress=cs@sshinjector.net
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:bd:da:30:b6:22:78:de:0d:d2:82:9f:42:9c:26:
                    98:3e:29:b7:ef:35:28:8b:23:cf:bd:7b:ba:33:c5:
                    14:64:57:9b:a4:fc:f3:e4:39:3d:2f:f3:e0:df:cd:
                    09:f0:5d:13:a9:fb:b6:4d:6e:34:b3:c4:9c:b2:ab:
                    b1:24:fc:11:08:cc:e8:98:6b:dc:a4:e7:d1:ae:bb:
                    d7:b0:ce:18:db:8a:9e:12:57:19:04:b7:a7:47:c0:
                    d5:36:7d:12:f8:36:2a:a6:05:48:9c:88:4a:09:8b:
                    8b:99:67:9f:89:93:65:78:8c:52:6f:52:78:0e:c2:
                    37:e3:c3:75:b6:92:60:39:85:bc:b3:5f:03:15:4f:
                    45:0a:b1:4e:78:d8:1e:46:fe:da:d3:c9:16:8f:04:
                    88:88:08:ba:70:e0:73:68:9d:7a:98:57:b2:2d:e3:
                    cf:e9:d3:9e:f5:1e:dd:b0:dc:bd:a0:ca:50:6c:9d:
                    2d:de:6a:af:c4:a9:ab:c4:82:d8:8f:5a:ae:0e:fd:
                    b6:d1:d5:e1:8d:e9:c9:06:56:4c:24:50:35:82:8e:
                    6b:42:8b:91:ff:31:ec:d1:f2:d9:e3:c7:71:c9:e1:
                    58:dc:6c:a1:af:88:9a:c3:e3:c1:3b:24:06:e3:13:
                    06:52:87:3e:33:eb:76:c1:92:3c:34:3a:75:51:72:
                    41:ef
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                B1:80:9C:AE:BE:C6:7C:5E:04:D2:11:0E:83:73:3B:BB:B6:DC:2F:FB
            X509v3 Authority Key Identifier: 
                keyid:C3:19:C3:F1:43:C1:3F:B7:97:DF:41:E3:67:63:D6:85:0E:5E:F6:DC
                DirName:/C=ID/ST=Jawa Tengah/L=Blora/O=Sshinjector.net/OU=Free Premium SSH dan VPN SSL/TLS Service/CN=Sshinjector.net CA/name=server/emailAddress=cs@sshinjector.net
                serial:D0:E8:D4:9A:FA:02:5F:B2
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         bd:d3:67:29:af:31:52:8a:cd:6d:2b:5a:31:0b:33:cb:72:d1:
         1c:fe:9a:79:d4:49:35:43:49:88:5c:ee:8f:5a:0e:25:7a:3f:
         4d:5f:7e:a6:26:00:e3:61:c3:d5:1b:97:54:dd:73:88:a9:8f:
         81:29:09:81:3d:ef:e0:95:a5:2c:05:81:b5:8a:f3:ce:0b:4f:
         3d:fc:27:64:a0:e3:6b:1c:cf:38:7d:f9:85:c2:42:d3:39:10:
         29:f3:e8:d2:bd:94:d3:e7:37:36:c4:ac:69:3d:a9:d0:18:4b:
         2c:9f:db:4a:a3:cf:89:9c:2b:43:7e:25:8a:21:9f:dd:07:6d:
         da:db:c0:87:a6:dd:fc:ed:0c:5f:a7:d7:81:96:d7:d4:73:10:
         f6:97:c1:79:22:3e:0a:7a:14:ba:da:d3:ae:66:59:70:cc:2d:
         b9:fd:44:cf:16:84:db:27:14:db:48:b1:24:af:48:f3:e2:d7:
         50:94:92:b2:74:fd:21:d0:62:5d:bd:b8:49:d3:85:78:6c:92:
         0f:5a:be:7b:ee:35:63:93:48:12:e7:e3:2f:36:2d:e7:16:ab:
         34:bb:1c:97:3c:97:95:ba:a1:aa:0a:f1:38:14:80:22:c8:84:
         28:cd:d0:e2:24:5f:d3:f2:28:24:38:c0:05:68:69:68:eb:4f:
         4b:ce:07:65
-----BEGIN CERTIFICATE-----
MIIFyzCCBLOgAwIBAgIBATANBgkqhkiG9w0BAQsFADCB0TELMAkGA1UEBhMCSUQx
FDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4wDAYDVQQHEwVCbG9yYTEYMBYGA1UEChMP
U3NoaW5qZWN0b3IubmV0MTEwLwYDVQQLEyhGcmVlIFByZW1pdW0gU1NIIGRhbiBW
UE4gU1NML1RMUyBTZXJ2aWNlMRswGQYDVQQDExJTc2hpbmplY3Rvci5uZXQgQ0Ex
DzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3DQEJARYSY3NAc3NoaW5qZWN0b3Iu
bmV0MB4XDTIwMDYxMTA0MDYxMloXDTMwMDYwOTA0MDYxMlowgcUxCzAJBgNVBAYT
AklEMRQwEgYDVQQIEwtKYXdhIFRlbmdhaDEOMAwGA1UEBxMFQmxvcmExGDAWBgNV
BAoTD1NzaGluamVjdG9yLm5ldDExMC8GA1UECxMoRnJlZSBQcmVtaXVtIFNTSCBk
YW4gVlBOIFNTTC9UTFMgU2VydmljZTEPMA0GA1UEAxMGc2VydmVyMQ8wDQYDVQQp
EwZzZXJ2ZXIxITAfBgkqhkiG9w0BCQEWEmNzQHNzaGluamVjdG9yLm5ldDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3aMLYieN4N0oKfQpwmmD4pt+81
KIsjz717ujPFFGRXm6T88+Q5PS/z4N/NCfBdE6n7tk1uNLPEnLKrsST8EQjM6Jhr
3KTn0a6717DOGNuKnhJXGQS3p0fA1TZ9Evg2KqYFSJyISgmLi5lnn4mTZXiMUm9S
eA7CN+PDdbaSYDmFvLNfAxVPRQqxTnjYHkb+2tPJFo8EiIgIunDgc2idephXsi3j
z+nTnvUe3bDcvaDKUGydLd5qr8Spq8SC2I9arg79ttHV4Y3pyQZWTCRQNYKOa0KL
kf8x7NHy2ePHccnhWNxsoa+ImsPjwTskBuMTBlKHPjPrdsGSPDQ6dVFyQe8CAwEA
AaOCAbYwggGyMAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgZAMDQGCWCGSAGG
+EIBDQQnFiVFYXN5LVJTQSBHZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0G
A1UdDgQWBBSxgJyuvsZ8XgTSEQ6Dczu7ttwv+zCCAQYGA1UdIwSB/jCB+4AUwxnD
8UPBP7eX30HjZ2PWhQ5e9tyhgdekgdQwgdExCzAJBgNVBAYTAklEMRQwEgYDVQQI
EwtKYXdhIFRlbmdhaDEOMAwGA1UEBxMFQmxvcmExGDAWBgNVBAoTD1NzaGluamVj
dG9yLm5ldDExMC8GA1UECxMoRnJlZSBQcmVtaXVtIFNTSCBkYW4gVlBOIFNTTC9U
TFMgU2VydmljZTEbMBkGA1UEAxMSU3NoaW5qZWN0b3IubmV0IENBMQ8wDQYDVQQp
EwZzZXJ2ZXIxITAfBgkqhkiG9w0BCQEWEmNzQHNzaGluamVjdG9yLm5ldIIJANDo
1Jr6Al+yMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIFoDARBgNVHREE
CjAIggZzZXJ2ZXIwDQYJKoZIhvcNAQELBQADggEBAL3TZymvMVKKzW0rWjELM8ty
0Rz+mnnUSTVDSYhc7o9aDiV6P01ffqYmAONhw9Ubl1Tdc4ipj4EpCYE97+CVpSwF
gbWK884LTz38J2Sg42sczzh9+YXCQtM5ECnz6NK9lNPnNzbErGk9qdAYSyyf20qj
z4mcK0N+JYohn90HbdrbwIem3fztDF+n14GW19RzEPaXwXkiPgp6FLra065mWXDM
Lbn9RM8WhNsnFNtIsSSvSPPi11CUkrJ0/SHQYl29uEnThXhskg9avnvuNWOTSBLn
4y82LecWqzS7HJc8l5W6oaoK8TgUgCLIhCjN0OIkX9PyKCQ4wAVoaWjrT0vOB2U=
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC92jC2InjeDdKC
n0KcJpg+KbfvNSiLI8+9e7ozxRRkV5uk/PPkOT0v8+DfzQnwXROp+7ZNbjSzxJyy
q7Ek/BEIzOiYa9yk59Guu9ewzhjbip4SVxkEt6dHwNU2fRL4NiqmBUiciEoJi4uZ
Z5+Jk2V4jFJvUngOwjfjw3W2kmA5hbyzXwMVT0UKsU542B5G/trTyRaPBIiICLpw
4HNonXqYV7It48/p0571Ht2w3L2gylBsnS3eaq/EqavEgtiPWq4O/bbR1eGN6ckG
VkwkUDWCjmtCi5H/MezR8tnjx3HJ4VjcbKGviJrD48E7JAbjEwZShz4z63bBkjw0
OnVRckHvAgMBAAECggEAEd1xTgJKa2LTl1UTOIxtMRRN6aWP7h/tkYAOEocOFy8j
R1BCRwyX1GZXl9e8grDPg+Ra0Eh5jx0GPc3oOnm5xKE7lfQ4bBAgbBfjAREzx5zw
qPsnMIlzpU3hAmKcoVy/gKXooko05VcLSOE2YwTKvKA/tZgGEiV2iuk+r3JwuZjR
ZYJjOrIkwl7mjP1d5v5/Npf+jpriYqqNBzwPNcG/rKoQErAGL8sQkbsAywp/sTUp
nuzpUTkVk3CafNkGmUQl4PqHXB7brf0VKHjQ6pnlrGd7j8oY7xdSUkl51XD1/Wuu
5Ck5cmQgveecKsKDMhnT2W4AvQgHfStafjNiA+IncQKBgQD0d2rwq7k6ZpOiP+Tf
3vyB5gY+w7jIC+oB3phLN+czRi1qHjxfeQf6hF3du9mDJOI+lZAKGuMTAu5yDbAB
sNh4Qcu95UaZTVp9hXUwdrneUtx/LEQyd0YH7LeCvjoXkERSbXY3vqvL3bGuZxdG
C53iskhbyGa/GIE4EbnlzHX2WQKBgQDGzylM21pe+HseLOpSxflfUVaIphVfXfxH
gO0v9eRr1W9IvFY/luRzdzS2JfE5QDgm7JLWYZaF8gBi3+X/vuM3Smr0ClBxRY0M
F7t7l+J1+aQPEdnrX+TckWMvrEPGzX12r7cgG7hF09/g1VmXrbI+7gCcTlh8f6UP
Mf21SJ8BhwKBgGTkD99pj5U5lj5EzklSNrXJX9RxZAYzXI0O9507YhB4Ku/7sIDa
a1+JV0/WYetMwo5/nSV+eS50bEHnwjbAbGYdCV/CisNj+C+Lb5Tjusu1OMjHVRHa
xa0plYbAySrGYFwATuSsrSwCv3yxkRpYWv2fBFvUtgqxq0qfji/3lMtpAoGBALiM
bWYu6QDn4EHup8YWiJp2wsEuiwBwGlO11neC5ntDMX5vdhCpXX/h1EiRiA8BEh7v
1I61IClOsBUYikSRShJ1Pjszp+C+E2R6U0szfsDM8AIdLBFWfvhQ7aW/X1sYPbMD
AhcIJFKNj3ECG5y1XJUWEfMGtxU62Fn2qfCybQfZAoGBAMxOzyjWbtRD7u05vx/n
N4UrP+1iow2RT7qcXP5tVcIVfL/XdDDIHpvBrrMzq+lkwUGxro56uNOjHH+C/1l5
al19/xPibKvMeUHOuuSGjP4fGzDkejdxVio/rAGTNrpUUqIFJxx+h85byN2dHNId
MzRXgYUDzClnV0mG+zRlv5/G
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF13'> /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAn36F3ypMmkE9/iJ0zduSSymg5ZHkciiwRgS/mua+hyZHwxQAGEN7
oD304NNxLv+kTt8lekc/bDjCnjfA3l/bUml72vRbOmqCiYWMx6VbyRWR9670jF8h
wQauhBS7EvW/Icvn5nWdskLgcFjdTDQ2+sT5/NOVURHLb0Lhx5YnslEweWb4584r
acVIEcsMsDLr2fpsh8KwpBwx3EwNuwzZjxR/SkegKNdajmcDOpTMaYXLKonrV1/j
btXGCCjYBnPXLGVQCkMLCu9T5wmu9V1Lkz8vsh959hM/5FSz15vnQ4PY3/MgKUZT
bNc/JITZzxeYwjWMUhMNGxYAOOpMdaOIqwIBAg==
-----END DH PARAMETERS-----
EOF13

 # Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
done

 # Creating a New update message in server.conf
 cat <<'NUovpn' > /etc/openvpn/server.conf
 # New Update are now released, OpenVPN Server
 # are now running both TCP and UDP Protocol. (Both are only running on IPv4)
 # But our native server.conf are now removed and divided
 # Into two different configs base on their Protocols:
 #  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
 #  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
 # 
 # Also other logging files like
 # status logs and server logs
 # are moved into new different file names:
 #  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
 #  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
 #  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
 #  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
 #
 # Server ports are configured base on env vars
 # executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
 #
 # Enjoy the new update
 # Script Updated by SigulaDev
NUovpn

 # setting openvpn server port
 sed -i "s|OVPNTCP|$OpenVPN_TCP_Port|g" /etc/openvpn/server_tcp.conf
 sed -i "s|OVPNUDP|$OpenVPN_UDP_Port|g" /etc/openvpn/server_udp.conf
 
 # Getting some OpenVPN plugins for unix authentication
 cd
 wget https://github.com/raziman869/AutoScriptDB/raw/master/Files/Plugins/plugin.tgz
 tar -xzvf /root/plugin.tgz -C /etc/openvpn/
 rm -f plugin.tgz
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
 sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
 sysctl --system &> /dev/null

 # Iptables Rule for OpenVPN server
 cat <<'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
 chmod +x /etc/openvpn/openvpn.bash
 bash /etc/openvpn/openvpn.bash

 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl enable openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_udp

}
function InsProxy(){

 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'privoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
privoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # Removing Duplicate Squid config
 rm -rf /etc/squid/squid.con*
 
 # Creating Squid server config using cat eof tricks
 cat <<'mySquid' > /etc/squid/squid.conf
# My Squid Proxy Server Config
acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:80
http_port 0.0.0.0:8080
http_port 0.0.0.0:8000
http_port 0.0.0.0:3128
### Allow Headers
request_header_access Allow allow all 
request_header_access Authorization allow all 
request_header_access WWW-Authenticate allow all 
request_header_access Proxy-Authorization allow all 
request_header_access Proxy-Authenticate allow all 
request_header_access Cache-Control allow all 
request_header_access Content-Encoding allow all 
request_header_access Content-Length allow all 
request_header_access Content-Type allow all 
request_header_access Date allow all 
request_header_access Expires allow all 
request_header_access Host allow all 
request_header_access If-Modified-Since allow all 
request_header_access Last-Modified allow all 
request_header_access Location allow all 
request_header_access Pragma allow all 
request_header_access Accept allow all 
request_header_access Accept-Charset allow all 
request_header_access Accept-Encoding allow all 
request_header_access Accept-Language allow all 
request_header_access Content-Language allow all 
request_header_access Mime-Version allow all 
request_header_access Retry-After allow all 
request_header_access Title allow all 
request_header_access Connection allow all 
request_header_access Proxy-Connection allow all 
request_header_access User-Agent allow all 
request_header_access Cookie allow all 
request_header_access All allow all
### HTTP Anonymizer Paranoid
reply_header_access Allow allow all 
reply_header_access Authorization allow all 
reply_header_access WWW-Authenticate allow all 
reply_header_access Proxy-Authorization allow all 
reply_header_access Proxy-Authenticate allow all 
reply_header_access Cache-Control allow all 
reply_header_access Content-Encoding allow all 
reply_header_access Content-Length allow all 
reply_header_access Content-Type allow all 
reply_header_access Date allow all 
reply_header_access Expires allow all 
reply_header_access Host allow all 
reply_header_access If-Modified-Since allow all 
reply_header_access Last-Modified allow all 
reply_header_access Location allow all 
reply_header_access Pragma allow all 
reply_header_access Accept allow all 
reply_header_access Accept-Charset allow all 
reply_header_access Accept-Encoding allow all 
reply_header_access Accept-Language allow all 
reply_header_access Content-Language allow all 
reply_header_access Mime-Version allow all 
reply_header_access Retry-After allow all 
reply_header_access Title allow all 
reply_header_access Connection allow all 
reply_header_access Proxy-Connection allow all 
reply_header_access User-Agent allow all 
reply_header_access Cookie allow all 
reply_header_access All deny all
### CoreDump
coredump_dir /var/spool/squid
dns_nameservers 8.8.8.8 8.8.4.4
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname proxy.sshinjector.net
mySquid

 # Setting machine's IP Address inside of our Squid config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "Restarting proxy server..."
 systemctl restart squid
}

function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/johnfordtv-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/johnfordtv-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

 # Now creating all of our OpenVPN Configs 

cat <<EOF15> /var/www/openvpn/Moonlight.ovpn90
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp
setenv FRIENDLY_NAME "sshinjector.net"
remote $IPADDR $OpenVPN_TCP_Port
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy $IPADDR $Privoxy_Port1
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER ""
http-proxy-option CUSTOM-HEADER "GET https://storage.googleapis.com HTTP/1.1"
http-proxy-option CUSTOM-HEADER Host storage.googleapis.com
http-proxy-option CUSTOM-HEADER X-Forward-Host storage.googleapis.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For storage.googleapis.com
http-proxy-option CUSTOM-HEADER Referrer storage.googleapis.com
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF15
cat <<EOF16> /var/www/openvpn/sun-tutcp.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp
setenv FRIENDLY_NAME "sshinjector.net"
remote $IPADDR $OpenVPN_TCP_Port
remote-cert-tls server
connect-retry infinite
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
comp-lzo
redirect-gateway def1
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
http-proxy $IPADDR $Squid_Port1
http-proxy-option CUSTOM-HEADER Host www.viber.com.edgekey.net
http-proxy-option CUSTOM-HEADER X-Online-Host www.viber.com.edgekey.net
http-proxy-option CUSTOM-HEADER X-Forwarded-For www.viber.com.edgekey.net
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF16
cat <<EOF162> /var/www/openvpn/sun-tuudp.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto udp
setenv FRIENDLY_NAME "sshinjector.net"
remote $IPADDR $OpenVPN_UDP_Port
remote-cert-tls server
resolv-retry infinite
float
fast-io
nobind
persist-key
persist-remote-ip
persist-tun
auth-user-pass
auth none
auth-nocache
cipher none
comp-lzo
redirect-gateway def1
setenv CLIENT_CERT 0
reneg-sec 0
verb 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF162
cat <<EOF17> /var/www/openvpn/sun-noload.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp-client
setenv FRIENDLY_NAME "MoonlightVPN"
remote $IPADDR $OpenVPN_TCP_Port
remote-cert-tls server
bind
float
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth none
auth-nocache
auth-retry interact
cipher none
comp-lzo
reneg-sec 0
verb 0
nice -20
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF17
cat <<EOF152> /var/www/openvpn/gtmwnp.ovpn
# t.me/sigula
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp-client
setenv FRIENDLY_NAME "sshinjector.net"
remote $IPADDR $OpenVPN_TCP_Port
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy $IPADDR $Privoxy_Port1
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER Host www.googleapis.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For www.googleapis.com
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF152
cat <<EOF1152> /var/www/openvpn/Moonlight.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp-client
setenv FRIENDLY_NAME "sshinjector.net"
remote $IPADDR $OpenVPN_TCP_Port
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 3
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy $IPADDR $Privoxy_Port1
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER Host shopee.ph
http-proxy-option CUSTOM-HEADER X-Online-Host shopee.ph
http-proxy-option CUSTOM-HEADER X-Forward-Host shopee.ph
http-proxy-option CUSTOM-HEADER Connection Keep-Alive
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF1152
cat <<EOF1632> /var/www/openvpn/Moonlight.ovpn
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp-client
setenv FRIENDLY_NAME "sshinjector.net"
remote $IPADDR $OpenVPN_TCP_Port
nobind
persist-key
persist-tun
comp-lzo
keepalive 10 120
tls-client
remote-cert-tls server
verb 2
auth-user-pass
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
redirect-gateway def1
setenv CLIENT_CERT 0
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy $IPADDR 3356
http-proxy-option CUSTOM-HEADER ""
http-proxy-option CUSTOM-HEADER "POST https://viber.com HTTP/1.1"
http-proxy-option CUSTOM-HEADER "X-Forwarded-For: viber.com"
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF1632

cat > /var/www/openvpn/tcp-client.ovpn <<END
# OpenVPN Configuration Dibuat Oleh Sshinjector.net
# (Contact Bussines: M Fauzan Romandhoni - m.fauzan58@yahoo.com)

client
dev tun
proto tcp
setenv FRIENDLY_NAME "sshinjector.net"
remote $MYIP $OpenVPN_TCP_Port
remote-cert-tls server
bind
float
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth none
auth-nocache
auth-retry interact
cipher none
comp-lzo
reneg-sec 0
verb 0
nice -20
<ca>
-----BEGIN CERTIFICATE-----
MIIFZDCCBEygAwIBAgIJANDo1Jr6Al+yMA0GCSqGSIb3DQEBCwUAMIHRMQswCQYD
VQQGEwJJRDEUMBIGA1UECBMLSmF3YSBUZW5nYWgxDjAMBgNVBAcTBUJsb3JhMRgw
FgYDVQQKEw9Tc2hpbmplY3Rvci5uZXQxMTAvBgNVBAsTKEZyZWUgUHJlbWl1bSBT
U0ggZGFuIFZQTiBTU0wvVExTIFNlcnZpY2UxGzAZBgNVBAMTElNzaGluamVjdG9y
Lm5ldCBDQTEPMA0GA1UEKRMGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJjc0Bzc2hp
bmplY3Rvci5uZXQwHhcNMjAwNjExMDQwNjEyWhcNMzAwNjA5MDQwNjEyWjCB0TEL
MAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4wDAYDVQQHEwVCbG9y
YTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQLEyhGcmVlIFByZW1p
dW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYDVQQDExJTc2hpbmpl
Y3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3DQEJARYSY3NA
c3NoaW5qZWN0b3IubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0K3vlvCxz3Rsx5y0SX90erEgCzFvpRJfQasAZaWKtnq/jbNt0ofIyY6l12yko6Ri
jvjljPcIUvfqWtwlNYTfP3I/UHO2Kd2635cGN6KMvLNsMsSqfFPndBl/okn/8ewD
6zmNFZ5H4FVXqB6YNZ6NYW2UTwzsxJjPsFVhiT/kzZ4dDB1m1gFSVC//NfWUZuvk
PuPet7rKHKwe6blrCcU0J+JhHLwSavZ6TNMVDAEBBqkk6cqEEcZ7GiW0sDfqEfkT
NsJh3WpllTIeqUokfh68oJVoLxI1RPPOdYONGNMVf/uPiNHLRi4S2Q+nVG4ePKdn
3s04NAVXCZF8KQ4MHH3C2wIDAQABo4IBOzCCATcwHQYDVR0OBBYEFMMZw/FDwT+3
l99B42dj1oUOXvbcMIIBBgYDVR0jBIH+MIH7gBTDGcPxQ8E/t5ffQeNnY9aFDl72
3KGB16SB1DCB0TELMAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4w
DAYDVQQHEwVCbG9yYTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQL
EyhGcmVlIFByZW1pdW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYD
VQQDExJTc2hpbmplY3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqG
SIb3DQEJARYSY3NAc3NoaW5qZWN0b3IubmV0ggkA0OjUmvoCX7IwDAYDVR0TBAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAinNNz43TcTf8ffvjJ1aKEQScaSuBXIT+
9C8PLXWOhOZIFDxAAA40HtZu8iCjtpCu0Z+rLxDqnu2+KSgiOZXxp4mS3ooa6j5B
ImeGIclzRgKPsSHZHU8VXXYdnPZP6KeBPWYnwc8bz9exG36Hpe9UBmvuWPtIAh2l
8eFNzTiOoJwdPP3HpELYoB70ES8F4LtoIVteaZCoDubay0HT36SFGg1sUQ+6DqYl
aRKiEUEkLjQAwe5Js8LtJTPWtrOpJvstmPJvCP38ycVIUBK/xrQl+PDKWE+7o2lA
9cS9EcGkLyGX1pKYWFiNbNKxgMWp34MmM9axxYwANj08l1ZEqVtEvw==
-----END CERTIFICATE-----
</ca>
END

cat > /var/www/openvpn/udp-client.ovpn <<END
# OpenVPN Configuration Dibuat Oleh Sshinjector.net
# (Contact Bussines: M Fauzan Romandhoni - m.fauzan58@yahoo.com)

client
dev tun
proto udp
setenv FRIENDLY_NAME "sshinjector.net"
remote $MYIP $OpenVPN_UDP_Port
remote-cert-tls server
bind
float
mute-replay-warnings
connect-retry-max 9999
redirect-gateway def1
connect-retry 0 1
resolv-retry infinite
setenv CLIENT_CERT 0
persist-tun
persist-key
auth-user-pass
auth none
auth-nocache
auth-retry interact
cipher none
comp-lzo
reneg-sec 0
verb 0
nice -20
<ca>
-----BEGIN CERTIFICATE-----
MIIFZDCCBEygAwIBAgIJANDo1Jr6Al+yMA0GCSqGSIb3DQEBCwUAMIHRMQswCQYD
VQQGEwJJRDEUMBIGA1UECBMLSmF3YSBUZW5nYWgxDjAMBgNVBAcTBUJsb3JhMRgw
FgYDVQQKEw9Tc2hpbmplY3Rvci5uZXQxMTAvBgNVBAsTKEZyZWUgUHJlbWl1bSBT
U0ggZGFuIFZQTiBTU0wvVExTIFNlcnZpY2UxGzAZBgNVBAMTElNzaGluamVjdG9y
Lm5ldCBDQTEPMA0GA1UEKRMGc2VydmVyMSEwHwYJKoZIhvcNAQkBFhJjc0Bzc2hp
bmplY3Rvci5uZXQwHhcNMjAwNjExMDQwNjEyWhcNMzAwNjA5MDQwNjEyWjCB0TEL
MAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4wDAYDVQQHEwVCbG9y
YTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQLEyhGcmVlIFByZW1p
dW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYDVQQDExJTc2hpbmpl
Y3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqGSIb3DQEJARYSY3NA
c3NoaW5qZWN0b3IubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0K3vlvCxz3Rsx5y0SX90erEgCzFvpRJfQasAZaWKtnq/jbNt0ofIyY6l12yko6Ri
jvjljPcIUvfqWtwlNYTfP3I/UHO2Kd2635cGN6KMvLNsMsSqfFPndBl/okn/8ewD
6zmNFZ5H4FVXqB6YNZ6NYW2UTwzsxJjPsFVhiT/kzZ4dDB1m1gFSVC//NfWUZuvk
PuPet7rKHKwe6blrCcU0J+JhHLwSavZ6TNMVDAEBBqkk6cqEEcZ7GiW0sDfqEfkT
NsJh3WpllTIeqUokfh68oJVoLxI1RPPOdYONGNMVf/uPiNHLRi4S2Q+nVG4ePKdn
3s04NAVXCZF8KQ4MHH3C2wIDAQABo4IBOzCCATcwHQYDVR0OBBYEFMMZw/FDwT+3
l99B42dj1oUOXvbcMIIBBgYDVR0jBIH+MIH7gBTDGcPxQ8E/t5ffQeNnY9aFDl72
3KGB16SB1DCB0TELMAkGA1UEBhMCSUQxFDASBgNVBAgTC0phd2EgVGVuZ2FoMQ4w
DAYDVQQHEwVCbG9yYTEYMBYGA1UEChMPU3NoaW5qZWN0b3IubmV0MTEwLwYDVQQL
EyhGcmVlIFByZW1pdW0gU1NIIGRhbiBWUE4gU1NML1RMUyBTZXJ2aWNlMRswGQYD
VQQDExJTc2hpbmplY3Rvci5uZXQgQ0ExDzANBgNVBCkTBnNlcnZlcjEhMB8GCSqG
SIb3DQEJARYSY3NAc3NoaW5qZWN0b3IubmV0ggkA0OjUmvoCX7IwDAYDVR0TBAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAinNNz43TcTf8ffvjJ1aKEQScaSuBXIT+
9C8PLXWOhOZIFDxAAA40HtZu8iCjtpCu0Z+rLxDqnu2+KSgiOZXxp4mS3ooa6j5B
ImeGIclzRgKPsSHZHU8VXXYdnPZP6KeBPWYnwc8bz9exG36Hpe9UBmvuWPtIAh2l
8eFNzTiOoJwdPP3HpELYoB70ES8F4LtoIVteaZCoDubay0HT36SFGg1sUQ+6DqYl
aRKiEUEkLjQAwe5Js8LtJTPWtrOpJvstmPJvCP38ycVIUBK/xrQl+PDKWE+7o2lA
9cS9EcGkLyGX1pKYWFiNbNKxgMWp34MmM9axxYwANj08l1ZEqVtEvw==
-----END CERTIFICATE-----
</ca>
END

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">
<!-- Simple OVPN Download -->
<head><meta charset="utf-8" /><head><meta name="robots" content="noindex" /></head>
<title>Automatic Script VPS by Sshinjector.net</title>
<body><pre><center><img src="https://1.bp.blogspot.com/-gpOb09BfB5w/XHpsdAZvDbI/AAAAAAAAAFY/0pJfvL2O3OsMxGVWR--KKXTZ7fmAGgU7wCLcBGAs/s320/faismartlogo.png" data-original-height="120" data-original-width="120" height="320" width="320"><b><br><br><font color="RED" size="50"><b>Setup by: M Fauzan Romandhoni</font><br><font color="BLUE" size="50">Whatsapp: 081311310405</font></b><br><br><font color="GREEN" size="50">SSHINJECTOR.NET</font><br></center></pre></body>
mySiteOvpn
 
 # Setting template's correct name,IP address and nginx Port
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html
 # Restarting nginx service
 systemctl restart nginx
 rm -f /var/www/openvpn/sun-tutcp.ovpn
 rm -f /var/www/openvpn/Moonlight.ovpn90
 rm -f /var/www/openvpn/sun-tuudp.ovpn
 rm -f /var/www/openvpn/sun-noload.ovpn
 rm -f /var/www/openvpn/gtmwnp.ovpn
 rm -f /var/www/openvpn/Moonlight.ovpn
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r client.zip *.ovpn
 cd
}
function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"
function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo -e "0 4\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job
 # Creating directory for startup script
 rm -rf /etc/Kyowoni
 mkdir -p /etc/Kyowoni
 chmod -R 755 /etc/Kyowoni
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/johnfordtv/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime
# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive
# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT
# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash
# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
exit 0
EOFSH
 cat <<'FordServ' > /etc/systemd/system/Kyowoni.service
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/Kyowoni/startup.sh
 # 
 rm -rf /etc/sysctl.d/99*
 # Setting our startup script to run every machine boots 
 cat <<'FordServ' > /etc/systemd/system/Kyowoni.service
[Unit]
Description=Kyowoni Startup Script
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash /etc/Kyowoni/startup.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
FordServ
 chmod +x /etc/systemd/system/Kyowoni.service
 systemctl daemon-reload
 systemctl start Kyowoni
 systemctl enable Sigula &> /dev/null
 systemctl enable fail2ban &> /dev/null
 systemctl start fail2ban &> /dev/null
 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}
 #Create Admin
 useradd -m admin
 echo "admin:itangsagli" | chpasswd
function ConfMenu(){
echo -e " Creating Menu scripts.."
cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://github.com/Kyowoni/AutoScriptMoon/raw/master/Files/Menu/bashmenu.zip'
unzip -qq bashmenu.zip
rm -f bashmenu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~
}
function ScriptMessage(){
 echo -e " [\e[1;32m$MyScriptName VPS Installer\e[0m]"
 echo -e ""
}
function InstBadVPN(){
 # Pull BadVPN Binary 64bit or 32bit
if [ "$(getconf LONG_BIT)" == "64" ]; then
 wget -O /usr/bin/badvpn-udpgw "https://github.com/Kyowoni/AutoScriptMoon/raw/master/Files/Plugins/badvpn-udpgw64"
else
 wget -O /usr/bin/badvpn-udpgw "https://github.com/Kyowoni/AutoScriptMoon/raw/master/Files/Plugins/badvpn-udpgw"
fi
 # Set BadVPN to Start on Boot via .profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000' /root/.profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100' /root/.profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200' /root/.profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /root/.profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400' /root/.profile
 sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500' /root/.profile
 # Change Permission to make it Executable
 chmod +x /usr/bin/badvpn-udpgw
 # Start BadVPN via Screen
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400
 screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500
}
#############################################
#############################################
########## Installation Process##############
#############################################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################################
#############################################
 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exiting..." 
 exit 1
fi
 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi
 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31mError\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi
 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure BadVPN UDPGW
 echo -e "Configuring BadVPN UDPGW..."
 InstBadVPN
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin
 
 # Configure Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs
 # Some assistance and startup scripts
 ConfStartup
 ## DNS maker plugin for SUN users(for vps script usage only)
 wget -qO dnsmaker "https://raw.githubusercontent.com/raziman869/raziman/master/Files/Plugins/debian"
 chmod +x dnsmaker
 ./dnsmaker
 rm -rf dnsmaker
 sed -i "s|http-proxy $IPADDR|http-proxy $(cat /tmp/abonv_mydns)|g" /var/www/openvpn/suntu-dns.ovpn
 sed -i "s|remote $IPADDR|remote $(cat /tmp/abonv_mydns)|g" /var/www/openvpn/sun-tuudp.ovpn
 curl -4sSL "$(cat /tmp/abonv_mydns_domain)" &> /dev/null
 mv /tmp/abonv_mydns /etc/bonveio/my_domain_name
 mv /tmp/abonv_mydns_id /etc/bonveio/my_domain_id
 rm -rf /tmp/abonv*
 # VPS Menu script v1.0
 ConfMenu
 
 # set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
 
 clear
 cd ~
 
  # Running screenfetch
 wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/Kyowoni/AutoScriptMoon/master/Files/Plugins/screenfetch"
 chmod +x /usr/bin/screenfetch
 echo "clear" >> .profile
 echo "screenfetch" >> .profile
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
echo " "
echo "Installation has been completed!!"
echo "--------------------------------------------------------------------------------"
echo "                            Debian Premium Script                               "
echo "--------------------------------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo "Server Information"  | tee -a log-install.txt
echo "   - Timezone    : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban    : [ON]"  | tee -a log-install.txt
echo "   - IPtables    : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot : [ON]"  | tee -a log-install.txt
echo "   - IPv6        : [OFF]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Application & Port Information"  | tee -a log-install.txt
echo "   - OpenVPN		: TCP $OpenVPN_TCP_Port UDP $OpenVPN_UDP_Port "  | tee -a log-install.txt
echo "   - OpenSSH		: $SSH_Port1, $SSH_Port2 "  | tee -a log-install.txt
echo "   - Dropbear		: $Dropbear_Port1, $Dropbear_Port2"  | tee -a log-install.txt
echo "   - Stunnel/SSL 	: $Stunnel_Port1, $Stunnel_Port2"  | tee -a log-install.txt
echo "   - Squid Proxy	: 80, 8080, 8000, 3128 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Privoxy		: $Privoxy_Port1 , $Privoxy_Port2 (limit to IP Server)"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Premium Script Information"  | tee -a log-install.txt
echo "   To display list of commands: menu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Important Information"  | tee -a log-install.txt
echo "   - Installation Log        : cat /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   - Webmin                  : http://$MYIP:10000/"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "OpenVPN Configs Download"  | tee -a log-install.txt
echo "   - Download Link           : http://$MYIP:81/client.zip"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "--------------------------------------------------------------------------------"  | tee -a log-install.txt
echo " Please Reboot your VPS"
 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f ip.sh
exit 1
