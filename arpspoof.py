'''
ARPSpoof Program by Clayton Johnson and Mitchell Bohn

Steps:
	Take IPs and find their MAC Addresses through ARP Request

'''
import argparse
import scapy
import threading

def get_mac_address(ip):
	#Make ARP Request to get MAC addy for given ip
	print(f'Making ARP Request for {ip}')

def clean_ip(addr):
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

def poison(arg1='arg1_default',arg2='arg2_default',arg3='arg3_default',arg4='arg4_default'):
	print(f'Poisoning: {arg1} {arg2} {arg3} {arg4}')

def start_sniffing_stuff(t_ip, t_mac, h_ip, h_mac):
	print('Sniffing initiated...')

def spoof_time(t_ip, h_ip):
	print(f'Target IP: {t_ip}')
	print(f'Host IP: {h_ip}')
	
	#Get MAC Addys for both target and host ips
	t_mac = get_mac_address(t_ip)
	h_mac = get_mac_address(h_ip)

	#Poison cache -> Saw an idea that split the cache poisoning to a separate thread to keep it constant
	# I like this idea...
	
	#Kick off thread to poison the cache
	poison_thread = threading.Thread(target=poison, args=('test1','test2','test3','test4'))
	poison_thread.run()

	#Receive traffic and output
	start_sniffing_stuff(t_ip, t_mac, h_ip, h_mac)

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
