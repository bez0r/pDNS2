#!/usr/bin/env python

# pDNS2 collector
# utility to parse DNS query and responses from pcaps or interface through tshark

import sys
import subprocess
import argparse
import datetime
import time
import string
import redis


def normalizeDate(date):
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


def makeDateTime(date):
    year = int(date[0:4])
    month = int(date[5:7])
    day = int(date[8:10])
    hour = int(date[11:13])
    minute = int(date[14:16])
    second = int(date[17:19])
    markup = str(year+month+day+hour+minute+second)
    return (markup)

def domain_truncate(no_dom):
    # truncate the domainlist to 2 zones
    subsplit = no_dom.split('.')
    z0 = subsplit[-1]
    z1 = subsplit[-2]
    domeval = str(z1)+'.'+str(z0)
    return(domeval)

options = None
AllInjest = []   

def main():
    global options
    
    parser = argparse.ArgumentParser(description='pDNS2 a tool to collect and store DNS request and responses. Requires Redis server running on default port.')
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('-f','--file',help='specifiy the file by path and name /path/to/file')
    parser.add_argument('-i','--interface',help='specify the interface name')
    args = parser.parse_args()

    if args.file:
	command = "/usr/bin/tshark -nnr "+str(args.file)+" -T fields -R \"dns.count.answers gt 0\" -e frame.time -e ip.src -e ip.dst -e dns.resp.type -e dns.resp.name -e dns.resp.ttl -e dns.resp.primaryname -e dns.resp.ns -e dns.resp.addr -E separator=\"|\"  2> /dev/null"
    elif args.interface:
	command = "/usr/bin/tshark -nni "+str(args.interface)+" -T fields -R \"dns.count.answers gt 0\" -e frame.time -e ip.src -e ip.dst -e dns.resp.type -e dns.resp.name -e dns.resp.ttl -e dns.resp.primaryname -e dns.resp.ns -e dns.resp.addr -E separator=\"|\"  2> /dev/null"
    else:
	print parser.description
	print 'you must supply either an interface with -i with the correct interface or -f with the path to the pcap file'
	sys.exit(-1)

    tshark = subprocess.Popen(command,stdout=subprocess.PIPE,shell=True)    

    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    r.ping
    while True:
        tshark.poll()                  
        line = tshark.stdout.readline() 
        if (line==''):
            print "End of line",line
            sys.exit(1)
        else: 
            line = line[:-1]  
            fields = line.split('|')     
            strdate = fields[0][:-10]
            dns_server = fields[1]            
            dns_client = fields[2]             
            rrecords = fields[3].split(',')    
            queries = fields[4].split(',')     
            ttls = fields[5].split(',')        
            cnames = fields[6].split(',')      
            nss = fields[7]
            ips = fields[8].split(',')
            date = normalizeDate(strdate)
	    consume_count = len(queries)
	    
	    for dom_take in range(consume_count):
		r.hset("Domain:"+queries[dom_take],"type",rrecords[dom_take])
		r.hset("Domain:"+queries[dom_take], "date",str(date))        
		r.hsetnx("Domain:"+queries[dom_take], "first",str(date))
		r.hset("Domain:"+queries[dom_take],"dns_client",dns_client) 
		r.hset("Domain:"+queries[dom_take],"dns_server",dns_server) 
		r.hset("Domain:"+queries[dom_take],"ttl",ttls[0])           
		r.hset("Domain:"+queries[dom_take],"ip",ips[0])             
		r.hset(queries[dom_take],"rr_type", cnames)                 
		if nss !="":
		    r.hset("Domain:"+queries[dom_take],"nss", nss) 
		r.hincrby("Domain:"+queries[dom_take], "count", amount=1) 

		ip_count = len(ips)
		for ip_take in range(ip_count):
		    r.hset("IP:"+ips[ip_take],"type", rrecords[ip_take]) 
		    r.hset("IP:"+ips[ip_take],"ttl",ttls[ip_take])       
		    r.hset("IP:"+ips[ip_take], "date",str(date))         
		    r.hsetnx("IP:"+ips[ip_take], "first",str(date))	
		    r.hset("IP:"+ips[ip_take], "name", queries[ip_take])
		    r.hset("Domain:"+queries[ip_take], "ip", ips[ip_take])
		    r.hincrby("IP:"+ips[ip_take], "count", amount=1)      

if __name__ == '__main__':
    main()


