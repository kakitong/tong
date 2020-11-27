#!/bin/bash
MYIP=$(wget -qO- ipv4.icanhazip.com);shre=#http_access;rpstat=''
until [[ $shr =~ Y|y|N|n ]]; do
	read -p "Shareable RP [Y]es [N]o : " shr
done
[[ $shr =~ N|n ]] && shre=http_access && rpstat=' not'
sq=$([ -d /etc/squid ] && echo squid || echo squid3)
wget -qO- https://raw.githubusercontent.com/kakitong/tong/main/1.sh && bash 1.sh | sed -e "s/#http_access/$shre/g" | sed -e "s/x.x.x.x/$MYIP/g" > /etc/$sq/squid.conf
# reload
systemctl restart {openvpn,$sq}
clear
wget -qO- "https://raw.githubusercontent.com/X-DCB/Unix/master/banner" | bash
echo 'Openvpn Server has been restarted.'
echo 'Squid Proxy has been restarted.'
echo 'Your Squid is'$rpstat' shareable.'
