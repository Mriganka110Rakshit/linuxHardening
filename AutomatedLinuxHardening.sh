#!/bin/bash
GREEN="\033[1;32m"
NOCOLOR="\033[0m"

echo -e "${GREEN}Updating the system...${NOCOLOR}"
sudo dpkg --configure -a #preconfigurepackages
sudo apt-get install -f  #fixbrokendependencies
sudo apt-get update	 #updatecache
sudo apt-get upgrade
sudo apt-get dist-upgrade
sudo apt-get --purge autoremove #removeunusedpackages
sudo apt-get autoclean	 	#cleanup

echo -e "${GREEN}Configuring firewall...${NOCOLOR}"
sudo iptables -F	#flushrules
sudo apt-get install iptables-persistent
sudo iptables -P INPUT DROP	#defaultdeny
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT -i lo -j ACCEPT	#loopbacktrafficconfig
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT #outboundtrafficconfig
sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p icmp -j DROP	#blockicmp
sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 100/minute --limit-burst 200 -j ACCEPT #blocknetworkfloodonapache80
sudo iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 3 -j REJECT	#limitconcurrentconnfrom1IP
sudo iptables-save > /etc/iptables/rules.v4
sudo iptables -L -v -n
sudo ip6tables -F        #flushrules
sudo ip6tables -P INPUT DROP     #defaultdeny
sudo ip6tables -P OUTPUT DROP
sudo ip6tables -P FORWARD DROP
sudo ip6tables -A INPUT -i lo -j ACCEPT  #loopbacktrafficconfig
sudo ip6tables -A OUTPUT -o lo -j ACCEPT
sudo ip6tables -A INPUT -s ::1 -j DROP
sudo ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT #outboundtrafficconfig
sudo ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
sudo ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
sudo ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
sudo ip6tables -A INPUT -p icmp -j DROP  #blockicmp
sudo ip6tables -A INPUT -p tcp --dport 80 -m limit --limit 100/minute --limit-burst 200 -j ACCEPT #blocknetworkfloodonapache80
sudo ip6tables -A INPUT -p tcp --syn -m connlimit --connlimit-above 3 -j REJECT       #limitconcurrentconnfrom1IP
sudo ip6tables-save > /etc/iptables/rules.v6
sudo ip6tables -L -v -n
sudo /etc/init.d/netfilter-persistent save

echo -e "${GREEN}Disabling USB...${NOCOLOR}"
sudo mv /lib/modules/$(uname -r)/kernel/drivers/usb/storage/usb-storage.ko /lib/modules/$(uname -r)/kernel/drivers/usb/storage/usb-storage.ko.blacklist

echo -e "${GREEN}Configuring password policies...${NOCOLOR}"
sudo apt-get install libpam-pwquality
sudo chmod 777 /etc/security/pwquality.conf
#sudo echo "minlen = 9">> /etc/security/pwquality.conf		#lengthofpass
#sudo echo "dcredit = -1">> /etc/security/pwquality.conf	#atleast1digit
#sudo echo "ucredit = -1">> /etc/security/pwquality.conf	#uppercase
#sudo echo "ocredit = -1">> /etc/security/pwquality.conf	#splchar
#sudo echo "lcredit = -1">> /etc/security/pwquality.conf	#lowercase
sudo chmod 644 /etc/security/pwquality.conf
sudo chmod 777 /etc/pam.d/common-auth
#sudo echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth #maxfailedtries
sudo chmod 644 /etc/pam.d/common-auth
sudo chmod 777 /etc/pam.d/common-account
#sudo echo "account required pam_tally.so" >> /etc/pam.d/common-account
sudo chmod 644 /etc/pam.d/common-account
sudo chmod 777 /etc/pam.d/common-password
#sudo echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password #oldpassreuse
sudo chmod 644 /etc/pam.d/common-password
sudo chmod 777 /etc/login.defs
#sudo sed -i 's/PASS_MAX_DAYS/PASS_MAX_DAYS   90\n#/' /etc/login.defs
#sudo sed -i 's/PASS_MIN_DAYS/PASS_MIN_DAYS   7\n#/' /etc/login.defs
sudo chmod 644 /etc/login.defs
sudo useradd -D -f 30                   #disableinactiveacc
sudo egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >uzerleest.txt
cat uzerleest.txt | while read in; do sudo chage --maxdays 90 "$in"; done
cat uzerleest.txt | while read in; do sudo chage --mindays 7 "$in"; done
cat uzerleest.txt | while read in; do sudo chage --inactive 30 "$in"; done
rm uzerleest.txt
#set all user shells required to /usr/sbin/nologin and lock the sync,shutdown and halt users
#for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do if [ $user != "root" ]; then sudo usermod -L $user; if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then $
sudo usermod -g 0 root  #setgid0forroot
sudo chmod 777 /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
#echo "umask 027" | sudo tee -a /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh	#defaultfilepermsn
#echo "TMOUT=600" | sudo tee -a /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh   #defaultshelltimeout
sudo chmod 644 /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
sudo chmod 777 /etc/pam.d/su
#echo "auth required pam_wheel.so" >> /etc/pam.d/su		#restrictsucommtousersinsudoerslist
sudo chmod 644 /etc/pam.d/su

echo -e "${GREEN}Configuring network parameters...${NOCOLOR}"
sudo chmod 777 /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0">> /etc/sysctl.conf               #disableipfowarding
echo "net.ipv6.conf.all.forwarding = 0">>/etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0">>/etc/sysctl.conf   #disableicmpredirect
echo "net.ipv4.conf.default.send_redirects = 0">>/etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0">>/etc/sysctl.conf      #denysourceroutedpackets
echo "net.ipv4.conf.default.accept_source_route = 0">>/etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0">>/etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0">>/etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0">>/etc/sysctl.conf         #denyicmpredirectedpackets
echo "net.ipv4.conf.default.accept_redirects = 0">>/etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0">>/etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0">>/etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0">>/etc/sysctl.conf         #denysecureicmpredirectedpackets
echo "net.ipv4.conf.default.secure_redirects = 0">>/etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1">>/etc/sysctl.conf             #logmaliciouspacket
echo "net.ipv4.conf.default.log_martians = 1">>/etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1">>/etc/sysctl.conf       #ignoreicmpbroadcst
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1">>/etc/sysctl.conf #ignorebogusicmpresponse
echo "net.ipv4.conf.all.rp_filter = 1">>/etc/sysctl.conf                #enablereversepathfiltering
echo "net.ipv4.conf.default.rp_filter = 1">>/etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1">>/etc/sysctl.conf                    #enabletcpsyncookie
sudo chmod 644 /etc/sysctl.conf
sudo sysctl -w net.ipv4.ip_forward=0                            #setactivekernelparameters
sudo sysctl -w net.ipv6.conf.all.forwarding=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.route.flush=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
sudo sysctl -w net.ipv6.conf.all.accept_source_route=0
sudo sysctl -w net.ipv6.conf.default.accept_source_route=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.route.flush=1
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.route.flush=1
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.log_martians=1
sudo sysctl -w net.ipv4.conf.default.log_martians=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.route.flush=1

echo -e "${GREEN}Disabling unused services...${NOCOLOR}"
sudo apt purge xinetd						#removingxinetd
sudo apt-get remove openbsd-inetd
sudo systemctl enable systemd-timesyncd.service
sudo chmod 777 /etc/systemd/timesyncd.conf			#timesyncconfig
echo "NTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org" >> /etc/systemd/timesyncd.conf
echo "FallbackNTP=ntp.ubuntu.com 3.ubuntu.pool.ntp.org" >> /etc/systemd/timesyncd.conf
echo "RootDistanceMaxSec=1" >> /etc/systemd/timesyncd.conf
sudo chmod 644 /etc/systemd/timesyncd.conf
sudo systemctl start systemd-timesyncd.service
sudo timedatectl set-ntp true
sudo systemctl --now disable avahi-daemon			#avahiserver
sudo systemctl --now disable cups				#communixprintsys
sudo systemctl --now disable isc-dhcp-server			
sudo systemctl --now disable isc-dhcp-server6
sudo systemctl --now disable slapd				#ldapserver
sudo systemctl --now disable nfs-server				#netfilesys
sudo systemctl --now disable rpcbind
sudo systemctl --now disable bind9				#dnsserver
sudo systemctl --now disable vsftpd				#ftpserver
sudo systemctl --now disable apache2				#httpserver
sudo systemctl --now disable dovecot				#emailservice
sudo systemctl --now disable smbd				#sambadaemon
sudo systemctl --now disable squid				#httpproxyserver
sudo systemctl --now disable snmpd				#snmpserver
sudo systemctl --now disable rsync	
sudo apt purge telnet						#unistalltelnet
sudo apt purge ldap-utils					#ldapclient

