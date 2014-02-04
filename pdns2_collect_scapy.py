#!/usr/bin/env python

# 
# this took works with the 'pDNS2' project to read either a pcap file or off the wire and populate a redis database tool

# this version requires scapy and redis imports
# scapy from http://www.secdev.org/projects/scapy/
# redis from https://github.com/andymccurdy/redis-py
# Keys are Domain and IP stored seperatly and this version 

## this version need the rr record for compataiblity with the tshark sourced data
## testing indicates scapy is a bit slower on the wire but faster on pcap collections

import scapy
#from scapy.all import *  # use if the other fields fail
from scapy.all import rdpcap
from scapy.all import sr1,IP,UDP,DNS,DNSQR,DNSRR  # pulls only what we need
from scapy.all import sniff
import sys,os
import redis
import datetime
import argparse

print 'scapy is not ideal for collecting on the wire, consider the tshark version'
print 'scapy works pretty well with pcaps, in fact you can spin up multiple instances at the same time'
print 'consider scapy only if you need a pure python instance'


# parsing arguments
parser = argparse.ArgumentParser(description='pDNS2 collector Requires Redis and scapy.')
group = parser.add_mutually_exclusive_group()
parser.add_argument('-f','--file',help='specifiy the file by path and name /path/to/file')
parser.add_argument('-i','--interface',help='specify the interface name')
args = parser.parse_args()

if args.file:
    a=rdpcap(str(args.file))
elif args.interface:
    print 'you might run into issues using scapy with pcapy'
    print 'visit http://stackoverflow.com/questions/17314510/how-to-fix-scapy-warning-pcapy-api-does-not-permit-to-get-capure-file-descripto'
    a = sniff(iface=args.interface, filter="udp and port 53")#prn=print_summary)
else:
    print parser.description
    print 'you must supply either an interface with -i with the correct interface or -f with the path to the pcap file'
    sys.exit(-1)


SearchList = ['rrname=','rdata=']

def value_sniper(arg1):
    string_it = str(arg1)
    snap_off = string_it.split('=')
    working_value = snap_off [1]
    return working_value[1:-1]


def normalizeDate(date):
    #unfortunate but wireshark/tshark does not offer time in unix format
    month = date[0:3]
    if month == 'Jan': month = '01'
    if month == 'Feb': month = '02'
    if month == 'Mar': month = '03'
    if month == 'Apr': month = '04'
    if month == 'May': month = '05'
    if month == 'Jun': month = '06'
    if month == 'Jul': month = '07'
    if month == 'Aug': month = '08'
    if month == 'Sep': month = '09'
    if month == 'Oct': month = '10'
    if month == 'Nov': month = '11'
    if month == 'Dec': month = '12'
    if date[4] == ' ':
            day = "0" + date[5]
    else:
            day = date[4:6]
    year = date[8:12]
    time = date[13:21]
    date_time_markup = year + month + day + " " + time
    #print date_time_markup
    return(date_time_markup)


def fix_type(arg1):
    ''' add 0x000 to the argument '''
    if arg1 >= 16:
        return "0x00%0X" % arg1
    else:
        return "0x000%0X" % arg1
    # single digits should look like 0x000
    # double digits should look like 0x00
    # This is about being consistent across versions


'''open a connection to the local redis database and assign to r'''
r = redis.StrictRedis(host='localhost', port=6379, db=2)
  



for pkt in a: # read the packet   
    if pkt.haslayer(DNSRR): ## Read in a pcap and parse out the DNSRR Layer
        domain1 = pkt[DNSRR].rrname   # this is the response, it is assumed
        
        if domain1 != '': # ignore empty and failures
            domain = domain1[:-1]

            pkt_type = pkt[DNSRR].type  # identify the response record that requires parsing
            rrtype = fix_type(pkt_type)

            
            #date/time
            time_raw = pkt.time # convert from unix to 8 digit date
            pkt_date = (datetime.datetime.fromtimestamp(int(time_raw)).strftime('%Y%m%d %H:%M:%S'))
            r.hsetnx("Domain:"+str(domain), "first",str(pkt_date))		# SET first seen for the domain
            r.hset("Domain:"+str(domain), "date",str(pkt_date))                # SET frame.time set to packet time

            dns_server = pkt[IP].src    # dns_server
            dns_client = pkt[IP].dst    # dns_client
            ttls =  pkt[DNSRR].ttl      # ttls
            r.hset("Domain:"+str(domain),"dns_client",dns_client)           # SET ip.src
            r.hset("Domain:"+str(domain),"dns_server",dns_server)           # SET ip.dst
            r.hset("Domain:"+str(domain),"ttl",ttls)                        # SET dns.resp.ttl
            r.hset("Domain:"+str(domain), "type",str(rrtype))             # SET record type
            r.hincrby("Domain:"+str(domain), "count", amount=1)    # dns.resp.addr COUNT increment


            if pkt_type == 2 or pkt_type == 5:  # this should work for type 5 and 2
                x = pkt[DNSRR].answers
                dns_strings = str(x)
                fields = dns_strings.split('|')
                for each in fields:
                    if 'type=NS' or 'type=A' in each:
                        subeach = str(each)
                        y = subeach.split(' ') # split lines
                        for subsubeach in y:
                            if 'rrname=' in subsubeach:
                                hold = value_sniper(subsubeach)
                                domain_hold = hold[:-1]
                            if 'rdata' in subsubeach:
                                ipaddress = value_sniper(subsubeach)
                                if ipaddress[-1:] != '.' and ipaddress[0] != '\\':                                
                                    r.hset("IP:"+str(ipaddress),"type", rrtype)                   # dns.resp.type    
                                    r.hset("IP:"+str(ipaddress),"ttl",ttls)                         # dns.resp.ttl
                                    r.hset("IP:"+str(ipaddress), "date",str(pkt_date))              # frame.time
                                    r.hsetnx("IP:"+str(ipaddress), "first",str(pkt_date))		# set first seen
                                    r.hset("IP:"+str(ipaddress), "name", domain_hold)                    # dns.resp.name
                                    r.hincrby("IP:"+str(ipaddress), "count", amount=1)              # dns.resp.add COUNT increment
                                if ipaddress != None:
                                    r.hset("Domain:"+str(domain), "ip", ipaddress)

            
            elif pkt_type == 1 or pkt_type == 12 or pkt_type == 28: #  32bit IP addresses
                ipaddress = pkt[DNSRR].rdata
                r.hset("Domain:"+str(domain),"ip",ipaddress)                         # dns.resp.addr
                r.hset("IP:"+str(ipaddress),"type", rrtype)                   # dns.resp.type

                r.hset("IP:"+str(ipaddress),"ttl",ttls)                         # dns.resp.ttl
                r.hset("IP:"+str(ipaddress), "date",str(pkt_date))              # frame.time
                r.hsetnx("IP:"+str(ipaddress), "first",str(pkt_date))		# set first seen
                r.hset("IP:"+str(ipaddress), "name", domain)                    # dns.resp.name
                r.hincrby("IP:"+str(ipaddress), "count", amount=1)              # dns.resp.add COUNT increment

            else:
                #pkt_type == 12: #ptr, just grab the domain, count and skip IP
                #print domain,pkt_type
                r.hset("Domain:"+str(domain), "ip", None)


    
print 'completed'





