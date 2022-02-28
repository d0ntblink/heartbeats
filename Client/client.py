#!/usr/bin/python3
from random import randint
from scapy.all import *

seq = 1
host = "0.0.0.0"
sport = random.randint(1024,65353)
dport = 11414
ip_packet = IP(dst=host)

def send_hello():
    global seq, ip_packet
    # sending the syn package and receiving SYN_ACK
    syn_packet = TCP(sport=sport, dport=dport, flags='S', seq=seq)
    packet = ip_packet/syn_packet
    
    synack_response = sr1(packet)
    seq += 1

    # sending the ACK back
    my_ack = synack_response.seq + 1
    ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=my_ack)

    send(ip_packet/ack_packet)
    seq += 1


    # sending the ACK with message
    payload_packet = TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=my_ack)
    payload = "hello its -A- me Mario"

    reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
    seq += 1

    # for r in reply:
    #     r[0].show2()
    # r[1].show2()
    
    
def send_termin() :
    global seq, ip_packet
    payload_packet = TCP(sport=sport, dport=dport, flags='R', seq=seq)
    payload = "TERMINATION, STOP TALKING TO ME"
    reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
    seq += 1
    
while True:
    usr_input = input().lower()
    if usr_input == "s" :
        send_hello()
    if usr_input == "t" :
        send_termin()
    else :
        print("NO >:(")