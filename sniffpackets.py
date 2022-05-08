#! /usr/bin/python

import socket
import os, sys
import struct
import binascii


sock_created = False
sniffer_socket = 0

def analyze_ip_header(data_recv):
	ip_hdr = struct.unpack('!6H4s4s', data_recv[:20]) # 20 bytes - ip protocol header size
	ver = ip_hdr[0] >> 12
	ihl = (ip_hdr[0] >> 8) & 0x0f
	tos = ip_hdr[0] & 0x00ff
	tot_len = ip_hdr[1]
	ip_id = ip_hdr[2]
	flag = ip_hdr[3] >> 13
	frag_offset = ip_hdr[3] & 0x1fff
	ip_ttl = ip_hdr[4] >> 8
	ip_proto = ip_hdr[4] & 0x00ff
	checksum = ip_hdr[5]
	src_address = socket.inet_ntoa(ip_hdr[6])
	dst_address = socket.inet_ntoa(ip_hdr[7])
	data = data_recv[20:]

	print("______________________IP HEADER________________")
	print("Version: %hu" %ver)
	print("IHL: %hu" % ihl)
	print("TOS: %hu" % tos)
	print("Length: %hu" % tot_len)
	print("ID: %hu" % ip_id)
	print("Flag: %hu" % flag)
	print("Offset: %hu" % frag_offset)
	print("TTL: %hu" % ip_ttl)
	print("Proto: %hu" % ip_proto)
	print("Checksum: %hu" % checksum)
	print("Source IP: %s" % src_address)
	print("Destination IP: %s" % dst_address)

	if ip_proto == 6:
		tcp_udp = "TCP"
	elif ip_proto == 17:
		tcp_udp = "UDP"
	else:
		tcp_udp = "OTHER"

	return data, tcp_udp


def analyze_ether_header(data_recv):
	ip_bool = False

	eth_hdr = struct.unpack('!6s6sH', data_recv[:14]) # take 1st 14 bytes (ethernet protocol header size)
	dest_mac = binascii.hexlify(eth_hdr[0]) # 1st 6 bites
	src_mac = binascii.hexlify(eth_hdr[1])
	proto = eth_hdr[2] >> 8
	data = data_recv[14:]

	print("________________ETHERNET HEADER________________")
	print("Destination Mac: %s:%s:%s:%s:%s:%s" % (dest_mac[0:2], dest_mac[2:4], dest_mac[4:6], dest_mac[6:8], dest_mac[8:10], dest_mac[10:12]))
	print("Source Mac: %s:%s:%s:%s:%s:%s" % (src_mac[0:2], src_mac[2:4], src_mac[4:6], src_mac[6:8], src_mac[8:10], src_mac[10:12]))
	print("PROTOCOL: %hu" % proto)

	if proto == 0x08: # if equals to hex of 8 - we got ip protocol
		ip_bool = True

	return data, ip_bool


def main():

	global sock_created
	global sniffer_socket

	if sock_created == False:
		sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
		sock_created = True

	data_recv = sniffer_socket.recv(2048)
	os.system("clear")

	data_recv, ip_bool = analyze_ether_header(data_recv)
	if ip_bool:
		data_recv, tcp_udp = analyze_ip_header(data_recv)
	else:
		return

	#if tcp_udp == "TCP":
	#	data_recv = analyze_tcp_header(data_recv)
	#elif tcp_udp == "UDP":
	#	data_recv = analyze_upd_header(data_recv)
	#else:
		return

while True:
	main()
