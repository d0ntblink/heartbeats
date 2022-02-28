#!/usr/bin/python3

import pcapy
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sniff

a_filter = "tcp[13] & 8!=0 and dst port 11414" # Captures TCP-PSH packets.
# devs = pcapy.findalldevs() # available devices
# print(devs)

def prnt_pckt(packet):
    # IP WRAP
    dst_ip = packet[IP].src
    src_ip = packet[IP].dst
    ip_ver = packet[IP].version
    ip_proto = packet[IP].proto
    # TCP WRAP
    tcp_src_p = packet[TCP].sport
    tcp_dst_p = packet[TCP].dport
    try:
        tcp_data = packet[TCP].load
    except:
        tcp_data = "empty packet"
    
    print('''
    src ip : {}
    dst ip : {}
    ip ver : {}
    ip proto : {}
    src port : {}
    dest port : {}
    data : {}
    '''.format(dst_ip, src_ip, ip_ver, tcp_src_p, ip_proto, tcp_dst_p, tcp_data))


sniff(filter=a_filter, prn=prnt_pckt)
# sniff(filter=a_filter, prn=lambda x: x.show())