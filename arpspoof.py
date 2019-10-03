import argparse
import scapy

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

def spoof_time(target, host):
	print(f'Target IP: {target}')
	print(f'Host IP: {host}')

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
