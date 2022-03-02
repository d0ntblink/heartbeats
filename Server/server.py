#!/usr/bin/python3
### LIBERARIES
import threading, logging
from random import randint
from time import sleep
from scapy.layers.inet import TCP, IP, Ether
from scapy.sendrecv import sniff, sr1, send, sr
from scapy.arch import get_if_addr, conf

### CONSTANTS
logging.basicConfig(level=logging.INFO, #                            to enable debugging mode:
                    format='\n%(asctime)s : %(threadName)s -- %(message)s\n') # <-- comment this
# logging.basicConfig(level=logging.DEBUG,
#                     format='\n%(asctime)s : %(threadName)s -- %(message)s\n') # <-- and uncomment this
local_ip = get_if_addr(conf.iface)
# https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters
bp_filter = "port 11414 && (dst host {localip})".format(localip=local_ip)
ip_list_dict = {}
ip_timeout_dict = {}
thread_list = []
seq = 1
logging.info('local ip : {}'.format(local_ip))
print('''
 ___  ___  _______   ________  ________  _________  ________  _______   ________  _________  ________      
|\  \|\  \|\  ___ \ |\   __  \|\   __  \|\___   ___\\\\   __  \|\  ___ \ |\   __  \|\___   ___\\\\   ____\     
\ \  \\\\\  \ \   __/|\ \  \|\  \ \  \|\  \|___ \  \_\ \  \|\ /\ \   __/|\ \  \|\  \|___ \  \_\ \  \___|_    
 \ \   __  \ \  \_|/_\ \   __  \ \   _  _\   \ \  \ \ \   __  \ \  \_|/_\ \   __  \   \ \  \ \ \_____  \   
  \ \  \ \  \ \  \_|\ \ \  \ \  \ \  \\\\  \|   \ \  \ \ \  \|\  \ \  \_|\ \ \  \ \  \   \ \  \ \|____|\  \  
   \ \__\ \__\ \_______\ \__\ \__\ \__\\\\ _\    \ \__\ \ \_______\ \_______\ \__\ \__\   \ \__\  ____\_\  \ 
    \|__|\|__|\|_______|\|__|\|__|\|__|\|__|    \|__|  \|_______|\|_______|\|__|\|__|    \|__| |\_________\\
                                                                                               \|_________|

Welcome to the Heatbeats Server!
Please make sure your heartbeats server is reachable by your clients.
Heartbeats server is only made of one way client to server communication.
Heartbeats sessions are not real TCP sessions, this is done to avoid the need to configure your firewall.
You can Access the most up-to-date version on: https://github.com/d0ntblink/heartbeats
\n\n
''')
#### VARIABLES
while True:
    try:
        timeout_limit = int(input("How long should the server wait before sending a PULSE? (in seconds) "))
        print("\n\n\nListening for messages ....")
        break
    except:
        logging.warning("Something went wrong, try again.")
logging.debug("timeout limit is {}.".format(timeout_limit))

#FUNCTIONS
def start_a_thread(thread_name, thread_function):
    logging.debug("start_a_thread is starting ...")
    global thread_list
    thread_name = threading.Thread(target=thread_function)
    thread_list.append(thread_name)
    thread_name.start()
    logging.debug("created thread %s.", thread_name)


def joining_threads():
    logging.debug("joinging threads is starting ...")
    global thread_list
    for t_num, thread in enumerate(thread_list):
        logging.debug("preparing to join thread %d.", t_num)
        thread.join()
        logging.debug("thread %d joined", t_num)
    

def analyze_pkt(packet):
    logging.debug("anlyze_pkt is starting ...")
    global ip_list_dict, ip_timeout_dict, local_ip
    logging.debug(packet.summary())
    # ETHERNET WRAP
    ip_proto = packet[Ether].type
    # IP WRAP
    dst_ip = packet[IP].dst
    src_ip = packet[IP].src
    ip_ver = packet[IP].version
    pkt_size = packet[IP].len
    # TCP WRAP
    tcp_src_p = packet[TCP].sport
    tcp_dst_p = packet[TCP].dport
    tcp_flag = packet[TCP].flags
    try:
        tcp_data = packet[TCP].load
    except:
        tcp_data = "0x00"
    # WHAT TO DO WITH PACKETS
    if tcp_flag == "S":
        if src_ip in ip_list_dict:
                if ip_list_dict[src_ip] != "open":
                    ip_list_dict[src_ip] = "open"
                    logging.info("heartbeat session with {ip} has been opened".format(ip=src_ip))
        else:
            ip_list_dict[src_ip] = "open"
            logging.info("heartbeat session with {ip} has been opened".format(ip=src_ip))
    elif tcp_flag == "A" and pkt_size > 40:
        ip_timeout_dict[src_ip] = int(0)
        if tcp_data == b'TERMINATE':
            ip_timeout_dict[src_ip] = int(0)
            ip_list_dict[src_ip] = "closed"
            logging.info("heartbeat session with {ip} has been closed".format(ip=src_ip))
        else:
            logging.info("{srip} said {msg}".format(srip=src_ip, msg=(str(tcp_data, 'utf-8'))))
            logging.debug('''
-- Ether INFO --
ip proto : {ipp}
-- IP INFO --
dst ip : {dsi}
src ip : {sri}
ip ver : {ipv}
pkt size : {pks}
-- TCP INFO --
tcp flag: {tcf}
src port : {srp}
dest port : {dsp}
data : {dat}
\n\n
            '''.format(ipp=ip_proto, dsi=dst_ip, sri=src_ip, ipv=ip_ver, pks=pkt_size, tcf=tcp_flag, srp=tcp_src_p, dsp=tcp_dst_p, dat=tcp_data))
    else:
        pass


def send_msg(msg, dst_ip, sport, dport):
    logging.debug("send_msg is starting ...")
    global seq
    ip_packet = IP(dst=(str(dst_ip)))
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
    logging.debug('%s %s' % (error, reply))
    seq += 1


def heartbeat():
    logging.debug("heartbeat is starting ...")
    global ip_list_dict, ip_timeout_dict, timeout_limit
    while True:
        sleep(1)
        for ip, sesh_stat in ip_list_dict.items():
            if sesh_stat == "open":
                ip_timeout_dict[ip] += 1
                logging.debug('{ip} hasnt replied for {sec} seconds'.format(ip=ip, sec=ip_timeout_dict[ip]))
                if ip_timeout_dict[ip] >= timeout_limit:
                    logging.warning("Session with {} timedout.".format(ip))
                    # Designated heartbeat port.
                    send_msg(msg="PULSE", dst_ip=ip, sport=randint(1024,65353), dport=11415)
                    logging.info("Sent a pulse to {}.".format(ip))
                else:
                    pass
            else:
                pass


def listening_for_pkts():
    logging.debug("listening_for_pkts starting ...")
    sniff(filter=bp_filter, prn=analyze_pkt)


start_a_thread(thread_name="a_very_good_listener", thread_function=listening_for_pkts)
start_a_thread(thread_name="a_caring_friend", thread_function=heartbeat)
# joining_threads()