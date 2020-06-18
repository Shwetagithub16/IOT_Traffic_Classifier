# -*- coding: utf-8 -*-
"""
Created on Sat May 16 11:45:48 2020

@author: Dev
"""

from scapy.all import rdpcap, wrpcap
import pandas as pd

def seperate_packets_wrt_MAC(file_path):

    packets_dict = {}
    devices_list = pd.read_csv('List_Of_Devices.csv', index_col='MAC ADDRESS')

    all_packets = rdpcap(file_path+'.pcap')
    for packet in all_packets:
        src = packet.fields['src']

        if src not in packets_dict.keys() :
            packets_dict[src] = []

        packets_dict[src].append(packet)

    for src in packets_dict.keys():
        dev_name = devices_list.loc[src][0]
        wrpcap(file_path+'_'+dev_name+'.pcap',packets_dict[src])

    print('Operation Complete')


