#!/bin/bash

#title           :perfectfirewall
#description     :simple, powerfull, DDOS copynpaste iptables firewall
#author		 :bartek@pewniak.net
#date            :20160801
#version         :0.1    
#==============================================================================

#apt-get install ipset iproute2

# change these variables
PUBLIC_IPS="192.168.0.12 192.168.0.13"
PUBLIC_INTERFACE=wlan0
TRUST_IPS="10.0.0.3 10.2.0.0/16"

ipset -exist create blocked_ips hash:ip timeout 1200

# clear all
# allow everything in case of error in the middle of the script - block at the end
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
iptables -X
iptables -F -t nat
iptables -F -t mangle
iptables -F -t raw

# to log just a part of all dropped
iptables -N DROPNLOG
iptables -A DROPNLOG -m limit --limit 10/second -j LOG --log-prefix DROPNLOG --log-level info
iptables -A DROPNLOG -j DROP

iptables -t mangle -A INPUT -m state --state INVALID -j DROP
iptables -t raw -A PREROUTING -i $PUBLIC_INTERFACE -p tcp -m tcp --syn -j CT --notrack
sysctl -w net/netfilter/nf_conntrack_tcp_loose=0
sysctl -w net/ipv4/tcp_timestamps=1
sysctl -w net/netfilter/nf_conntrack_max=2000000
echo 2000000 > /sys/module/nf_conntrack/parameters/hashsize


############ INPUT ############
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -i $PUBLIC_INTERFACE -p tcp -m tcp -m state --state INVALID,UNTRACKED  -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
for IP in $TRUST_IPS; do
    iptables -A INPUT -i $PUBLIC_INTERFACE -s $IP -j ACCEPT
done


# limit connections from source ip
iptables -A INPUT -i $PUBLIC_INTERFACE -m connlimit --connlimit-above 50 -j SET --add-set blocked_ips src
iptables -A INPUT -i $PUBLIC_INTERFACE -m connlimit --connlimit-above 200 --connlimit-mask 24 -j DROPNLOG
iptables -A INPUT -i $PUBLIC_INTERFACE -m state --state NEW  -m hashlimit --hashlimit-above 500/minute --hashlimit-mode srcip --hashlimit-name limit_new -j SET --add-set blocked_ips src


iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT




############ OUTPUT ############
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -o $PUBLIC_INTERFACE -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $PUBLIC_INTERFACE -m state --state NEW,RELATED -m limit --limit 100/second -p tcp --dport 21 -j ACCEPT
iptables -A OUTPUT -o $PUBLIC_INTERFACE -m state --state NEW -m limit --limit 100/second -p tcp -j ACCEPT
iptables -A OUTPUT -o $PUBLIC_INTERFACE -m state --state NEW -m limit --limit 100/second -p udp -j ACCEPT
iptables -A OUTPUT -o $PUBLIC_INTERFACE -m state --state NEW -m limit --limit 100/second -p icmp -j ACCEPT




############ FINISH ############

iptables -A INPUT -j DROPNLOG
iptables -A FORWARD -j DROPNLOG
iptables -A OUTPUT -j DROPNLOG







 
