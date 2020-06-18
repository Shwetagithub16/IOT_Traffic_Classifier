from scapy.all import*
from os import listdir
from os.path import isfile, join
import os
import datetime
import numpy as np
import csv
import math


a = []
b = []
path = "/media/root/8272-171E/Device_wise/00_24_e4_1b_6f_96/"
#path = "/root/Data/D/"
for f in os.listdir(path):
	if os.path.isfile(os.path.join(path, f)):
		a.append(path+f)

a.sort(key = lambda x: str(x.split('.')[0]))		

#print(a)
for i in a:
	data = rdpcap(i)
	
	sessions = data.sessions()
	Sess = len(sessions)
	#print(Tot_Sess)		
	count=0				
	flag=0
	sum=0
	c = 0
	FV,ST,FD,AFR,Tot_Sess=0,0,0,0,0
	t1,t2,t=0,0,0
	sport,dport,pbytes,DTTL,NTPD,DN,len_qname,ws,ttl = 0,0,0,0,0,0,0,0,0
	temp_ipv6src, temp_ipv6dst, temp_ethrsrc, temp_ethrdst,temp_psrc, temp_pdst,temp_ipsrc, temp_ipdst, temp_sport, temp_dport=0,0,0,0,0,0,0,0,0,0
	for k, v in sessions.iteritems():
		print(k,v)
		for p in v :
			try:
				if TCP in p :
										
					flag=0
					c= len(p)
					t1 = p.time%60
					
					if(p[IP].src!=temp_ipsrc or p[IP].dst!=temp_ipdst or p[TCP].sport != temp_sport or p[TCP].dport!=temp_dport):
						
							flag=1
							
					if(flag==1):
							#sum=0
							sum = c
							
							t= t1
							count=1
							
					else:
							sum=sum +c
							t2=p.time%60
							t= t+t1
							
							count=count+1
					temp_ipsrc, temp_ipdst, temp_sport, temp_dport = p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport
					#t3=t1-t2
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(sum,FD,AFR)
					
					
			except:
				pass
			#print(c,FV, k)
			try:
				if UDP in p :
										
					flag=0
					c= len(p)
					t1 = p.time%60
					if(p[IP].src!=temp_ipsrc or p[IP].dst!=temp_ipdst or p[UDP].sport != temp_sport or p[UDP].dport!=temp_dport):
						
							flag=1
					if(flag==1):
							#sum=0
							sum = c
							t=t1
							count=1
					else:
							sum=sum +c
							t2=p.time%60
							t=t+t1
							count=count+1
					temp_ipsrc, temp_ipdst, temp_sport, temp_dport = p[IP].src, p[IP].dst, p[UDP].sport, p[UDP].dport
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(c,sum,ST, k)
					
			except:
				pass
			#print(c,sum,ST,k)
			try:
				if ICMP in p :
										
					flag=0
					c= len(p)
					t1= p.time%60
					if(p[IP].src!=temp_ipsrc or p[IP].dst!=temp_ipdst):
							flag=1
					if(flag==1):
							#sum=0
							sum = c
							t=t1
							count=1
					else:
							sum=sum +c
							t2=p.time%60
							t=t+t1
							count=count+1
					temp_ipsrc, temp_ipdst = p[IP].src, p[IP].dst
					#print(c,sum, k)
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(c,sum, k)
			except:
				pass
			try:
				if p[IPv6].nh == 58 or p[IPv6].nh == 0:
										
					flag=0
					c= len(p)
					t1= p.time%60
					if(p[IPv6].src!=temp_ipv6src or p[IPv6].dst!=temp_ipv6dst):
							flag=1
					if(flag==1):
							#sum=0
							sum = c
							t=t1
							count=1
					else:
							sum=sum +c
							t2=p.time%60
							t=t+t1
							count=count+1
					temp_ipv6src, temp_ipv6dst = p[IPv6].src,p[IPv6].dst
					#print(c,sum, k)
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(c,sum, k)
			except:
				pass
			try:
				if ARP in p  :
										
					flag=0
					c= len(p)
					t1= p.time%60
					if(p[ARP].psrc!=temp_psrc or p[ARP].pdst!=temp_pdst ):
							flag=1
					if(flag==1):
							#sum=0
							sum = c
							t=t1
							count=1
					else:
							sum=sum +c
							t2=p.time%60
							t=t+t1
							count=count+1
					temp_psrc, temp_pdst = p[ARP].psrc, p[ARP].pdst
					#print(c,sum, k)
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(c,FV, k)
			except:
				pass
			
			try:
				if EAPOL in p  :
										
					flag=0
					c= len(p)
					t1= p.time%60
					if(p[Ether].src!=temp_ethrsrc or p[Ether].dst!=temp_ethrdst ):
							flag=1
					if(flag==1):
							#sum=0
							sum = c
							t=t1
							count=1
					else:
							sum=sum +c
							t2=p.time%60
							t=t+t1
							count=count+1
					temp_ethrsrc, temp_ethrdst = p[Ether].src, p[Ether].dst
					#print(c,sum, k)
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(c,FV, k)
			except:
				pass
			#print(c,FV, k)
			try:
				if p[IP].proto == 2:
										
					flag=0
					c= len(p)
					t1= p.time%60
					if(p[IP].src!=temp_ipsrc or p[IP].dst!=temp_ipdst):
							flag=1
					if(flag==1):
							#sum=0
							sum = c
							t=t1
							count=1
					else:
							sum=sum +c
							t2=p.time%60
							t=t+t1
							count=count+1
					temp_ipsrc, temp_ipdst = p[IP].src, p[IP].dst
					#print(c,sum, k)
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(c,FV, k)
			except:
				pass
			try:
				if UDP in p :
										
					flag=0
					c= len(p)
					t1 = p.time%60
					if(p[IPv6].src!=temp_ipv6src or p[IPv6].dst!=temp_ipv6dst):
						
							flag=1
					if(flag==1):
							#sum=0
							sum = c
							t=t1
							count=1
					else:
							sum=sum +c
							t2=p.time%60
							t=t+t1
							count=count+1
					temp_ipv6src, temp_ipv6dst = p[IPv6].src, p[IPv6].dst
					FV= sum
					ST = abs(t1-t2)
					FD = t
					AFR= (FV/FD)
					#print(c,sum,ST, k)
					
			except:
				pass
			#print(c,sum,ST, k)
			try:
				if UDP in p and DNS in p:
					if  p[DNS].rd == 1 and p[DNS].ra == 1 :
												
						DTTL = p[DNSRR].ttl
						
					if p[DNS].rd == 1 :
						DN = p[DNSQR].qname
						len_qname=len(DN)
					#print(DTTL, DN,len_qname)
			except:
				pass
			try:
				if UDP in p and NTP in p :
					if p[NTP].mode == 3 :
						NTPD = 2**(p[NTP].poll)
						 
						#print(NTPD, k)
			except: 
				pass
			try:
				if UDP in p :
					sport=p[UDP].sport
					dport=p[UDP].dport
					ttl = p[IP].ttl
					pbytes= len(p[UDP].payload)
					#print(port)
			except:
				pass
			try:
				if TCP in p :
					sport=p[TCP].sport
					dport=p[TCP].dport
					ws = p[TCP].window
					ttl = p[IP].ttl
					pbytes= len(p[TCP].payload)
					#print(proto)
			except:
				pass
		#Data = ['t1', 'sport', 'dport', 'pbytes', 'DTTL', 'NDPD', 'DN', 'len_qname', 'ws', 'ttl']
			#print(sum,ST,k)
		#print(FV,FD,AFR,count,Sess,k)
		#print("{},{},{},{},{},{},{},{},{},{}".format(t1, sport,dport,pbytes, DTTL, NTPD,DN,len_qname,ws,ttl))'''

