#!/usr/bin/python3

import threading, logging
from random import randint
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sniff, sr1, send, sr
from scapy.arch import get_if_addr


seq = 1
local_ip = get_if_addr(conf.iface)
sport = randint(1024,65353)
dport = 11414
heartbeat_filter = "port 11415 && dst host {localip}".format(local_ip=local_ip)
thread_list = []


def start_a_thread(thread_name, thread_function,thread_num):
    global thread_list
    thread_name = threading.Thread(target=thread_function, args=(thread_num,))
    thread_list.append(thread_name)
    # logging.info("starting thread %d.", thread_num)
    thread_name.start()


def joining_threads():
    global thread_list
    for t_num, thread in enumerate(thread_list):
        # logging.info("preparing thread %d.", t_num)
        thread.join()
        # logging.info("thread %d joined", t_num)


def send_msg(msg):
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
    payload = msg
    reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
    seq += 1
    # for r in reply:
    #     r[0].show2()
    # r[1].show2()


def looking_for_pulese(packet):
    # IP WRAP
    src_ip = packet[IP].dst
    pkt_size = packet[IP].len
    # TCP WRAP
    tcp_flag = packet[TCP].flags
    try:
        tcp_data = packet[TCP].load
    except:
        tcp_data = "00"
    # WHAT TO DO WITH PACKETS
    if ( tcp_flag == "A" ) and ( pkt_size >= 45 ) and ( tcp_data == "PULSE"):
        logging.info("Recieved a Pulse from {heartbeat_src}".format(heartbeat_src=src_ip))
    else:
        pass


def user_interface():
        ip_packet = IP(dst=(input("Please input the ip address of the server you are trying to connect to: ")))
        while True:
            usr_input = input('''
                              What would like to do:
                                S) Send a custom message
                                Q) Terminate session and change server IP
                                E) Exit the program
                                \n\n
                              ''').lower()
            # print(usr_input)
            if usr_input == "s" :
                send_msg(msg=input("What is your message : "))
                logging.info("Message Sent!")
                continue
            elif usr_input == "q" :
                send_msg(msg="TERMINATE")
                user_interface()
            elif usr_input == "e" :
                exit()
            else :
                print("Wrong Input, Please Try Again!\n\n")
                continue



start_a_thread(thread_name="hearbeat", thread_function=sniff(filter=heartbeat_filter, prn=looking_for_pulese), thread_num=2)
start_a_thread(thread_name="interface", thread_function=user_interface(), thread_num=1)
joining_threads()