#!/usr/bin/python3
### LIBERARIES
import threading, logging
from random import randint
from time import sleep
from scapy.layers.inet import TCP, IP, Ether
from scapy.sendrecv import sniff, sr1, send, sr
from scapy.arch import get_if_addr, conf

### CONSTANTS
logging.basicConfig(level=logging.DEBUG,
                    format='\n%(asctime)s : %(threadName)s -- %(message)s\n')
local_ip = get_if_addr(conf.iface)
# https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters
bp_filter = "port 11414 && (dst host {localip})".format(localip=local_ip)
ip_list_dict = {}
ip_timeout_dict = {}
thread_list = []
seq = 1
logging.debug('local ip : {}'.format(local_ip))

#FUNCTIONS
def start_a_thread(thread_name, thread_function):
    global thread_list
    thread_name = threading.Thread(target=thread_function)
    thread_list.append(thread_name)
    logging.debug("starting thread %s.", thread_name)
    thread_name.start()


def joining_threads():
    global thread_list
    for t_num, thread in enumerate(thread_list):
        logging.debug("preparing thread %d.", t_num)
        thread.join()
        logging.debug("thread %d joined", t_num)
    

def analyze_pkt(packet):
    global ip_list_dict, ip_timeout_dict, local_ip
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
        tcp_data = "0x00"
    # WHAT TO DO WITH PACKETS
    if tcp_flag == "S":
        logging.debug(packet.summary())
        ip_list_dict[dst_ip] = "open"
        logging.debug("heartbeat session with {ip} has been opened".format(ip=dst_ip))
    elif tcp_flag == "A" and pkt_size > 40:
        ip_timeout_dict[dst_ip] = int(0)
        if tcp_data == b'TERMINATE':
            ip_timeout_dict[dst_ip] = int(0)
            ip_list_dict[dst_ip] = "closed"
            logging.debug("heartbeat session with {ip} has been closed".format(ip=dst_ip))
        else:
            print('''
-- Ether INFO --
ip proto : {ipp}
--IP INFO--
dst ip : {dsi}
src ip : {sri}
ip ver : {ipv}
pkt size : {pks}
--TCP INFO--
tcp flag: {tcf}
src port : {srp}
dest port : {dsp}
data : {dat}
\n\n
            '''.format(ipp=ip_proto, dsi=dst_ip, sri=src_ip, ipv=ip_ver, pks=pkt_size, tcf=tcp_flag, srp=tcp_src_p, dsp=tcp_dst_p, dat=tcp_data))
    else:
        pass


def send_msg(msg, dst_ip, sport, dport):
    global seq
    ip_packet = IP(dst=(str(dst_ip)))
    # sending the syn package and receiving SYN_ACK
    syn_packet = TCP(sport=sport, dport=dport, flags='S', seq=seq)
    packet = ip_packet/syn_packet
    logging.debug(packet.show())
    synack_response = sr1(packet)
    seq += 1
    # sending the ACK back
    my_ack = synack_response.seq + 1
    ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=my_ack)
    logging.debug(ack_packet.summary())
    send(ip_packet/ack_packet)
    seq += 1
    # sending the ACK with message
    payload_packet = TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=my_ack)
    payload = msg
    reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
    logging.debug('%s %s' % (error, reply))
    seq += 1


def heartbeat():
    logging.debug("heartbeat is starting")
    global ip_list_dict, ip_timeout_dict
    while True:
        sleep(1)
        for ip in ip_list_dict:
            sesh_stat = ip_list_dict[ip]
            logging.debug('{} : {}'.format(ip, sesh_stat))
            if sesh_stat == "open":
                ip_timeout_dict[ip] += 1
                logging.debug('{ip} hasnt replied for {sec} seconds'.format(ip=ip, sec=ip_timeout_dict[ip]))
                if ip_timeout_dict[ip] >= 10:
                    logging.warning("Session with %s timedout.", ip)
                    # Designated heartbeat port.
                    send_msg(msg="PULSE", dst_ip=ip, sport=11415, dport=11415)
                    logging.debug("Sent a pulse to %s.")
                else:
                    pass
            else:
                pass


def listening_for_pkts():
    logging.debug("sniffing starting")
    sniff(filter=bp_filter, prn=analyze_pkt)


start_a_thread(thread_name="a_very_good_listener", thread_function=listening_for_pkts)
start_a_thread(thread_name="a_caring_friend", thread_function=heartbeat)
# joining_threads()