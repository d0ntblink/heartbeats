#!/usr/bin/python3

from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sniff

a_filter = "port 11414 && (tcp[13] & 8!=0)" # Captures TCP-PSH packets.
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
    tcp_flag = packet[TCP].flags
    try:
        tcp_data = packet[TCP].load
    except:
        tcp_data = "empty packet"
    
    print('''
    dst ip : {}
    src ip : {}
    ip ver : {}
    ip proto : {}
    tcp flag: {}
    src port : {}
    dest port : {}
    data : {}
    '''.format(dst_ip, src_ip, ip_ver, ip_proto, tcp_flag, tcp_src_p, tcp_dst_p, tcp_data))


sniff(filter=a_filter, prn=prnt_pckt)
# sniff(filter=a_filter, prn=lambda x: x.show())