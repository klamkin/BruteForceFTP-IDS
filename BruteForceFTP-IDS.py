#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet
import subprocess
import socket, sys
import datetime
from struct import *
import thread
from time import sleep

ips = {}
ipTimes = {} # we can add a specific time to each IP's first login attempt, instead of having just 1 generic 60 second resetter
ipPacketSizes = {}
packets_per_login = 6 #the number of packets that are sent for a login attempt, we can try dividing the number of total packets by this to approximate login attempts
bruteForceIntervalCounts = {}

def checkTimes():
	while True:
		for key in ipTimes:
			ipTimes[key] = ipTimes[key] + 1
			if ipTimes[key] > 60:
				if len(ipPacketSizes[key]) > 0:
					largePacketFound = False
					for packetSize in ipPacketSizes[key]:
						if packetSize > 95 and largePacketFound == False: #checking to see if only small packets have been used, higher probability of log in packets if less than 95 bytes in size
							largePacketFound = True #odds are user is already logged in and they are transfering data
							print 'Large packet found, user from ip ' + key + ' probably logged in'
					if largePacketFound == False and ips[key]/packets_per_login > 10: #there was no packet found over 90 bytes for that ip in that minute, and they could have tried logging in > 10 times
							try:
								bruteForceIntervalCounts[key] = bruteForceIntervalCounts[key] + 1 #add 1 to the total amount of intervals they could have been trying a brute force, need 3 in row for warning
							except:
								bruteForceIntervalCounts[key] = 1

							if bruteForceIntervalCounts[key] >= 3:
								print key + ' could be trying to brute force the ftp server!'

					elif key in bruteForceIntervalCounts: #reset the count, since this interval there was no suspicious behaviour, probably no brute force
						bruteForceIntervalCounts[key] = 0

				ips[key] = 0 #reset the count for this IP
				ipTimes[key] = 0
				ipPacketSizes[key] = []		
		sleep(1)

def main():
	try:
		thread.start_new_thread( checkTimes, () )
	except:
		print ("Thread failed to start")
	watchingPort = "21" 
	 
	#create an INET, STREAMing socket
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	 
	# receive a packet
	while True:
		packet = s.recvfrom(65565)
	   
		#packet string from tuple
		packet = packet[0]
	     
		#take first 20 characters for the ip header
		ip_header = packet[0:20]
		packetSizeBytes = len(packet)
		
		iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF
	     
		iph_length = ihl * 4 
		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
	     
		tcp_header = packet[iph_length:iph_length+20]
	     
		#now unpack them :)
		tcph = unpack('!HHLLBBHHH' , tcp_header)
	     
		source_port = tcph[0]
		dest_port = tcph[1]

		try:
			ipPacketSizes[str(s_addr)].append(packetSizeBytes)
		except:
			ipPacketSizes[str(s_addr)] = []
			ipPacketSizes[str(s_addr)].append(packetSizeBytes)

		if str(dest_port) == watchingPort:
			try:		
				ips[str(s_addr)] = ips[str(s_addr)] + 1
			except:
				ips[str(s_addr)] = 1
				ipTimes[str(s_addr)] = 1		



if __name__ == '__main__':
	main()
