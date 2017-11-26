#!/bin/bash

#title           :atomicfirewall.sh
#description     :simple, powerfull, DDOS copynpaste iptables firewall
#                : We purposely don't want any config files or arguments
#                   - script must be short, easy understandable, and should work on most internet systems without any tweaks.
#                   You can simply execute it in /etc/rc.local
#author          :bartek@pewniak.net
#version         :0.3    
#==============================================================================

#apt-get install ipset iproute2

PUBLIC_INTERFACE=`ip route get 8.8.8.8 | grep dev | awk '{print $5}'`
PUBLIC_IPS=`ip address show dev $PUBLIC_INTERFACE | grep 'inet ' | awk '{print $2}' | cut -f 1 -d '/' | while read ip ; do echo -n "$ip "; done`
TRUSTED_IPS="10.0.0.0/8 192.168.0.0/16"

############ CLEAR ############
# allow everything in case of error in the middle of the script - we will deny at the end
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -X

############ MISC ############
sysctl -w net/netfilter/nf_conntrack_tcp_loose=0
sysctl -w net/ipv4/tcp_timestamps=1
sysctl -w net/netfilter/nf_conntrack_max=2000000
echo 2000000 > /sys/module/nf_conntrack/parameters/hashsize
ipset destroy blocked_ips
ipset create blocked_ips hash:ip timeout 1200

iptables -t mangle -A INPUT -m state --state INVALID -j DROP
iptables -t raw -A PREROUTING -i $PUBLIC_INTERFACE -p tcp -m tcp --syn -j CT --notrack
iptables -t raw -A PREROUTING -i $PUBLIC_INTERFACE -m set --match-set blocked_ips src -j DROP

# to log just a part of all dropped
iptables -N DROPNLOG
iptables -A DROPNLOG -m limit --limit 10/second -j LOG --log-prefix DROPNLOG --log-level info
iptables -A DROPNLOG -j DROP

############ INPUT ############
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -i $PUBLIC_INTERFACE -p tcp -m tcp -m state --state UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460

# whitelist
for IP in $TRUSTED_IPS; do
    iptables -A INPUT -i $PUBLIC_INTERFACE -s $IP -j ACCEPT
done

# limit connections from source ip
iptables -A INPUT -i $PUBLIC_INTERFACE -m connlimit --connlimit-above 50 -j SET --add-set blocked_ips src
iptables -A INPUT -i $PUBLIC_INTERFACE -m connlimit --connlimit-above 200 --connlimit-mask 24 -j DROPNLOG
iptables -A INPUT -i $PUBLIC_INTERFACE -m state --state NEW  -m hashlimit --hashlimit-above 500/minute --hashlimit-mode srcip --hashlimit-name limit_new -j SET --add-set blocked_ips src

# Yes :) this is the place where you define your internet services. 
iptables -A INPUT -i $PUBLIC_INTERFACE -m state --state NEW -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -i $PUBLIC_INTERFACE -m state --state NEW -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i $PUBLIC_INTERFACE -m state --state NEW -p icmp -j ACCEPT
# iptables -A INPUT -i $PUBLIC_INTERFACE -m state --state NEW -p tcp --dport 25 -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT

############ OUTPUT ############
iptables -A OUTPUT -j ACCEPT

############ FINISH ############
iptables -A INPUT -j DROPNLOG
iptables -A FORWARD -j DROPNLOG
iptables -A OUTPUT -j DROPNLOG

