#!/usr/bin/python3

from scapy.layers.inet import TCP, IP, Ether
from scapy.sendrecv import sniff
from scapy.all import *


local_ip = get_if_addr(conf.iface)
a_filter = "port 11414"
# devs = pcapy.findalldevs() # available devices
# print(devs)
ip_list_dict = {}

def prnt_pckt(packet):
    global ip_list_dict, local_ip
    # ETHERNET WRAP
    ip_proto = packet[Ether].type
    # IP WRAP
    dst_ip = packet[IP].src
    src_ip = packet[IP].dst
    ip_ver = packet[IP].version
    pkt_size = packet[IP].len
    # TCP WRAP
    tcp_src_p = packet[TCP].sport
    tcp_dst_p = packet[TCP].dport
    tcp_flag = packet[TCP].flags
    try:
        tcp_data = packet[TCP].load
    except:
        tcp_data = "empty packet"
    

    if tcp_flag == "S":
        if src_ip != local_ip and (src_ip not in ip_list_dict):
            ip_list_dict[src_ip] = "open"
            print(ip_list_dict)
    elif tcp_flag == "A" and pkt_size >= 45:
        if tcp_data == b'TERMINATE':
            ip_list_dict[src_ip] = "closed"
            print(ip_list_dict)
        else:
            print('''
            -- Ether INFO --
            ip proto : {}
            --IP INFO--
            dst ip : {}
            src ip : {}
            ip ver : {}
            pkt size : {}
            --TCP INFO--
            tcp flag: {}
            src port : {}
            dest port : {}
            data : {}
            '''.format(ip_proto, dst_ip, src_ip, ip_ver, pkt_size, tcp_flag, tcp_src_p, tcp_dst_p, tcp_data))
    else:
        pass
    
sniff(filter=a_filter, prn=prnt_pckt)
# sniff(filter=a_filter, prn=lambda x: x.show())