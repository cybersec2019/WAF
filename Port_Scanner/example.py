# Python program to illustrate the concept
# of threading
import threading
import os
import socket
import struct
import sys
import datetime
import pprint
import time
from collections import Counter
from itertools import chain


def tcp_dissect(transport_data):
    # Extract information from transport_data
    # ! means programmer don't need to care about big endian or little endian
    # H -> source_port is 2 bytes, #H -> dest_port is 2 bytes
    # Unpack -> extract infromation in transport_data into different part depends on the format
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port


def udp_dissect(transport_data):
    # Extract information from transport_data
    # ! means programmer don't need to care about big endian or little endian
    # H -> source_port is 2 bytes, #H -> dest_port is 2 bytes
    # Unpack -> extract infromation in transport_data into different part depends on the format
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port


def icmp_dissect(transport_data):
    # Extract information from transport_data
    # ! means programmer don't need to care about big endian or little endian
    # B -> typeOfMessage is a byte, #B -> code is a byte
    # Unpack -> extract infromation in transport_data into different part depends on the format
    typeOfMessage, code = struct.unpack('!BB', transport_data[:2])
    return typeOfMessage, code


def ipv4_dissect(ip_data):
    # Extract information from ip_data
    # ! means programmer don't need to care about big endian or little endian
    # 9x (Skip 9 bytes) #B ->  (ip_protocol) #2x (Skip 2 bytes) #4s -> source ip is 4 bytes, target ip is 4 bytes
    # Unpack -> extract infromation in ip_data into different part depends on the format
    ip_protocol, source_ip, target_ip = struct.unpack('!9x B 2x 4s 4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]


def ipv4_format(address):
    return '.'.join(map(str, address))


def ethernet_dissect(ethernet_data):
    # Extract information from ip_data
    # ! means programmer don't need to care about big endian or little endian
    # 6s -> dest_mac is 6 bytes, src_mac is 6 bytes , protocol is a byte
    # Unpack -> extract infromation in ethernet_data into different part depends on the format
    dest_mac, src_mac, protocol = struct.unpack('!6s6sH', ethernet_data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]


def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()


def sniff(table):
    # PF_PACKET family get direct link-level access to the underlying hardware(Ethernet or similar). Can be used for packet capturing
    # SOCK_RAW means pass the packet to the application needs it. No TCP/IP processing mean the application responsbile for stripping off the headers, analyzing the packet
    # all the stuff the tcp/ip stack in kernel normally does.
    packets = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    startTime = datetime.datetime.utcnow()
    while True:

        # if((datetime.datetime.utcnow() - startTime).total_seconds() >= 15):
        #  return 0
        # I think it should be here hash table
        # recvfrom uses to receive message from a socket, wait for a message to arrive
        pkt, address = packets.recvfrom(65536)
        # Strip off ethernet header
        dest_mac, src_mac, protocol, datalink_data = (ethernet_dissect(pkt))
        # protocol = 8 meaning this is an IPv4
        if protocol == 8:
            # Strip off ipv4 header
            ip_protocol, src_ip, dest_ip, transport_data = ipv4_dissect(datalink_data)
            # TCP
            if ip_protocol == 6:
                # Strip off tcp header

                src_port, dest_port = tcp_dissect(transport_data)
                # print('source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3}, protocol:{4}, source port:{5}, dest port:{6}'.format(src_mac, dest_mac, src_ip, dest_ip, ip_protocol, src_port, dest_port))
                table.append(dict({'source_ip': src_ip, 'dest_ip': dest_ip, 'dest_port': dest_port,
                                   'timestamp': datetime.datetime.utcnow()}))
            # UDP
            if ip_protocol == 17:
                # Strip off udp header

                src_port, dest_port = udp_dissect(transport_data)
                # print('source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3}, protocol:{4}, source port:{5}, dest port:{6}'.format(src_mac, dest_mac, src_ip, dest_ip, ip_protocol, src_port, dest_port))
                table.append(dict({'source_ip': src_ip, 'dest_ip': dest_ip, 'dest_port': dest_port,
                                   'timestamp': datetime.datetime.utcnow()}))


# Older than 5 minutes got deleted
def clearTable(table):
    while (True):
        currentTime = datetime.datetime.utcnow()
        newHash = []
        for i in table:
            if ((currentTime - i['timestamp']).total_seconds() < 5):
                newHash.append(i)
        table = newHash


def fanOutRate(table):
    while (True):
        # Assume right now we only identify one attacker ip address
        startTime = datetime.datetime.utcnow()
        time.sleep(1)
        endTime = datetime.datetime.utcnow()
        diff = (endTime - startTime).total_seconds()
        # > 5 request Per seconds
        if len(table) >= 5 and diff <= 1 or len(table) >= 100 and diff <= 60 or len(table) >= 300 and diff <= 300:
            print(table[0]['source_ip'])


def PS_detector_example():
    # Hashtable will be global variables and pass to each process
    print(datetime.datetime.utcnow())
    table = []
    t1 = threading.Thread(target=sniff, args=(table,))
    t2 = threading.Thread(target=pprint.pprint, args=(table,))
    t3 = threading.Thread(target=clearTable, args=(table,))
    t4 = threading.Thread(target=fanOutRate, args=(table,))
    # starting thread 1
    t1.start()
    # starting thread 2
    t2.start()
    # starting thread 3
    t3.start()
    # starting thread 4
    t4.start()
    # wait until thread 1 is completely executed
    t1.join()
    # wait until thread 2 is completely executed
    t2.join()
    # wait until thread 3 is completely executed
    t3.join()
    # wait until thread 4 is completely executed
    t4.join()
    # both threads completely executed
    print("Done!")

