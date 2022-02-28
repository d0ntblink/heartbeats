#!/usr/bin/python3
from random import randint
from scapy.all import *

seq = 1
host = "10.0.0.231"
sport = random.randint(1024,65353)
dport = 11414

def send_hello():
    ip_packet = IP(dst=host)
    syn_packet = TCP(sport=sport, dport=dport, flags='S', seq=seq)

    packet = ip_packet/syn_packet
    synack_response = sr1(packet)

    next_seq = seq + 1
    my_ack = synack_response.seq + 1

    ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)

    send(ip_packet/ack_packet)

    payload_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)
    payload = "I am once again sending a packet to say hello"

    reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
    # for r in reply:
    #     r[0].show2()
    # # r[1].show2()
    
send_hello()