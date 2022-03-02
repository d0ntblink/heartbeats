#!/usr/bin/python3
### LIBERARIES
import threading, logging, sys
from time import sleep
from random import randint
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sniff, send, sr, sr1
from scapy.arch import get_if_addr, conf

### CONSTANTS
logging.basicConfig(level=logging.INFO, #                                           to enable debugging mode
                    format='\n%(asctime)s : %(threadName)s -- %(message)s\n') # <-- comment this
# logging.basicConfig(level=logging.DEBUG,
#                     format='\n%(asctime)s : %(threadName)s -- %(message)s\n') # <-- and uncomment this
seq = 1
local_ip = get_if_addr(conf.iface)
sport = randint(1024,65353)
dport = 11414
heartbeat_filter = "port 11415 && (dst host {localip})".format(localip=local_ip)
logging.debug(heartbeat_filter)
thread_list = []
logging.info('local ip : {}'.format(local_ip))
### WELCOME MESSAGE
print('''
 ___  ___  _______   ________  ________  _________  ________  _______   ________  _________  ________      
|\  \|\  \|\  ___ \ |\   __  \|\   __  \|\___   ___\\\\   __  \|\  ___ \ |\   __  \|\___   ___\\\\   ____\     
\ \  \\\\\  \ \   __/|\ \  \|\  \ \  \|\  \|___ \  \_\ \  \|\ /\ \   __/|\ \  \|\  \|___ \  \_\ \  \___|_    
 \ \   __  \ \  \_|/_\ \   __  \ \   _  _\   \ \  \ \ \   __  \ \  \_|/_\ \   __  \   \ \  \ \ \_____  \   
  \ \  \ \  \ \  \_|\ \ \  \ \  \ \  \\\\  \|   \ \  \ \ \  \|\  \ \  \_|\ \ \  \ \  \   \ \  \ \|____|\  \  
   \ \__\ \__\ \_______\ \__\ \__\ \__\\\\ _\    \ \__\ \ \_______\ \_______\ \__\ \__\   \ \__\  ____\_\  \ 
    \|__|\|__|\|_______|\|__|\|__|\|__|\|__|    \|__|  \|_______|\|_______|\|__|\|__|    \|__| |\_________\\
                                                                                               \|_________|

Welcome to the Heatbeats Client!
Before sending messages, make sure the heartbeats server is already running and reachable.
\n\n\
''')

### FUNCTIONS
def start_a_thread(thread_name, thread_function):
    logging.debug("start_a_thread is starting ...")
    global thread_list
    thread_name = threading.Thread(target=thread_function)
    thread_list.append(thread_name)
    thread_name.start()
    logging.debug("created thread %s.", thread_name)


def joining_threads():
    logging.debug("joining_threads is starting ...")
    global thread_list
    for t_num, thread in enumerate(thread_list):
        logging.debug("preparing thread %d.", t_num)
        thread.join()
        logging.debug("thread %d joined", t_num)


def send_msg(msg):
    logging.debug("send_msg is starting ...")
    global seq, ip_packet
    # sending the syn package and receiving SYN_ACK
    syn_packet = TCP(sport=sport, dport=dport, flags='S', seq=seq)
    packet = ip_packet/syn_packet
    logging.debug(packet.show())
    synack_response = sr1(packet)
    seq += 1
    # sending the ACK back
    my_ack = synack_response.seq + 1
    ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=my_ack)
    logging.debug(ack_packet.show())
    send(ip_packet/ack_packet)
    seq += 1
    # sending the ACK with message
    payload_packet = TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=my_ack)
    payload = msg
    reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
    logging.debug('%s %s' % (error, reply))
    seq += 1


def looking_for_pulse(packet):
    logging.debug("looking_for_pulse is starting ...")
    # IP WRAP
    src_ip = packet[IP].dst
    pkt_size = packet[IP].len
    # TCP WRAP
    tcp_flag = packet[TCP].flags
    try:
        tcp_data = packet[TCP].load
    except:
        tcp_data = "0x00"
    # WHAT TO DO WITH PACKETS
    if tcp_data == b'PULSE':
        logging.info("Recieved a Pulse from {heartbeat_src}".format(heartbeat_src=src_ip))
        send_msg(msg="STILL D.R.E")
        logging.info("Responded back to the PULSE from {heartbeat_src}".format(heartbeat_src=src_ip))
    else:
        pass


def user_interface():
    logging.debug("user_interface is starting ...")
    global ip_packet
    try:
        ip_packet = IP(dst=(input("Please input the ip address of the server you are trying to connect to: ")))
    except:
        logging.warning("Something went wrong, try again!")
        user_interface()
    while True:
        usr_input = input('''
What would like to do:
S) Send a customized message ->
Q) Terminate session and change server IP ->
E) Exit the program ->
\n
''').lower()
        sleep(1)
        logging.debug(usr_input)
        if usr_input == "s" :
            send_msg(msg=input("What is your message : "))
            logging.debug("Message Sent!")
            continue
        elif usr_input == "q" :
            send_msg(msg="TERMINATE")
            logging.debug("sent a terminate command")
            user_interface()
        elif usr_input == "e" :
            sys.exit()
        else :
            logging.warning("Unknown Input, Please try again!")
            continue


def listening_for_pulse():
    global heartbeat_filter
    sniff(filter=heartbeat_filter, prn=looking_for_pulse)


### START -->
start_a_thread(thread_name="user_interface", thread_function=user_interface)
start_a_thread(thread_name="i_need_a_doctor", thread_function=listening_for_pulse)
# joining_threads()