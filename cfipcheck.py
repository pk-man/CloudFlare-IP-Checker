#!/usr/bin/python2.7
import sys, socket, struct
from netaddr import *

cf_ipv4 = [
		'199.27.128.0/21',
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/12'
	  ]

cf_ipv6 = [ 
		'2400:cb00::/32', 
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32'
	  ]

class main:
	def __init__(self, check_if_cf):
		self.result = []
		self.check_if_cf = check_if_cf
		check_ip = IPAddress(check_if_cf)
		if check_ip.version is 6:
			self.ipv6()
		elif check_ip.version is 4:
			self.ipv4()
		self.check()

	def ipv4(self):
		try:
			ipaddr = struct.unpack('>L', socket.inet_aton(self.check_if_cf))[0]	
		except socket.error:
			print "[+] Invalid IP/Domain"
			return
		for x in cf_ipv4:
			netaddr, bits = x.split('/')
			netmask = (0xffffffff << (32 - int(bits)) & 0xffffffff)
			netaddr = struct.unpack('>L', socket.inet_aton(netaddr))[0]
			self.result.append(str(ipaddr & netmask == netaddr))	
	
	def ipv6(self):
		for x in cf_ipv6:
			ip = IPNetwork(x)
			ipaddr = IPAddress(self.check_if_cf)
			self.result.append(str(int(ipaddr) & int(ip.netmask) == int(ip.network)))

	def check(self):
		if "True" in self.result:
			print "[+] %s is a CloudFlare IP" % self.check_if_cf
			return
		else:
			print "[+] %s is NOT a CloudFlare IP" % self.check_if_cf
			return

if __name__ == "__main__":
	if len(sys.argv) > 4 or len(sys.argv) is 1:
		print "[+] Correct usages:"
                print "[+] %s <IPv4/IPv6>" % sys.argv[0]
                print "[+] %s -h <domain>" % sys.argv[0]	
	elif sys.argv[1].lower() == '-h':
		main(str(socket.gethostbyname(str(sys.argv[2]))))
	else:
		main(str(sys.argv[1]))
