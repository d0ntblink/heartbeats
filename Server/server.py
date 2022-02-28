#!/usr/bin/python3

from curses.ascii import ETB
from struct import pack
from scapy.layers.inet import TCP, IP, Ether
from scapy.sendrecv import sniff

a_filter = "port 11414" # Captures TCP-PSH packets.
# devs = pcapy.findalldevs() # available devices
# print(devs)
ip_list_dict = {}

def prnt_pckt(packet):
    global ip_list_dict
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
        if src_ip in ip_list_dict :
            pass
        else:
            ip_list_dict[src_ip] = "open"
            print(ip_list_dict)
    elif tcp_flag == "A" and pkt_size >= 60:
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
    elif tcp_flag == "R":
        ip_list_dict[src_ip] = "closed"
        print(ip_list_dict)
    else:
        pass
    
sniff(filter=a_filter, prn=prnt_pckt)
# sniff(filter=a_filter, prn=lambda x: x.show())