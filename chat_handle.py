from scapy.all import sniff, IP, TCP, sendp, Raw, show_interfaces
from mailing import time_now, parse_packet, chat_struct
import struct 
import config
from convert_packets import *
from start import start
from actions_db import *


def handle_packet_chat(packet):
    if IP in packet and TCP in packet:
        if (packet[IP].src == config.IP_SERVER and packet[IP].dst == config.IP_USER and
                packet[TCP].sport == config.PORT_SERVER):
            payload = packet[TCP].payload
            if payload:
                try:

                    data = payload.load
                    parsed_packet = parse_packet(data)
                    # print(parsed_packet)
                    if len(parsed_packet) > 3:
                        if (parsed_packet[2] == 'A'):
                            message = chat_struct(data)
                            if message is not None:
                                print(f"{message['ID']} - {message['nick']}: {message['text']}")
                                create_update_hero(message['ID'], message['nick'])
                except:
                    print("хз")

sniff(iface="Intel(R) Wi-Fi 6 AX201 160MHz", prn=handle_packet_chat, filter="ip and tcp", store=0)