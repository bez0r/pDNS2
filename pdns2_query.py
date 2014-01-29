#!/usr/bin/env python

# pDNS2 query, public release
# utility to query pDNS2 data


import datetime
import time
import argparse
import sys
from string import count
from collections import Counter
import redis  



def record_translate(rrecord):
    '''Resolves records by type'''
    # http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
    # http://en.wikipedia.org/wiki/List_of_DNS_record_types
    if rrecord == '0x0001':
        rrtype = "A"    # a host address
    elif rrecord == '0x0002':
        rrtype = "NS"   # a name server
    elif rrecord == '0x0005':
        rrtype = "CNAME"    # cononical name
    elif rrecord == '0x000f': #MX carries a  higher risk
        rrtype = 'MX'       # mail exchange, should only work with a mail exchange, isolate this type of DNS from host
    elif rrecord == '0x0006':
        rrtype = 'SOA'  # start of a zone authority
    elif rrecord == '0x000c':
        rrtype = "PTR"  # name pointer
    elif rrecord == '0x0010':
        rrtype = "TXT"   # watch this one, because it supports 189 bytes per record, sometime an exfil channel
    elif rrecord == '0x001c':
        rrtype = "AAAA" # ipv6
    elif rrecord == '0x0029':
        rrtype = "OPT"      # optional (used with DNSSEC)
    elif rrecord == '0x002e':
        rrtype = 'RRSIG'    # resource register digital signature
    elif rrecord == '0x0021':
        rrtype = 'SRV'      # server selection
    elif rrecord == '0x002f':
        rrtype = 'NSEC'     # authenticated denial of existence
    elif rrecord == '0x0032':
        rrtype = 'NSEC3'    # authenticated denial of existenc v3?
    elif rrecord == '0x002b':
        rrtype = 'DS'       # delegation signer
    elif rrecord == '0x00fa':
        rrtype = 'TSIG'     # transaction security mechanisms 
    else:   # Encountered a RR type we weren't prepared for
        rrtype = 'unknown' # unknown record types could carry a risk
    return(rrtype)



def header_dom():
    ''' header and linked to domain searched output'''
    print "{0:40} {1:15} {2:9} {3:9} {4:5} {5:5} {6:9}".format ("Domain","ips","first","date","rr","ttl","count")
    pass

def dom_print(sublist):
    ''' print the queried list in a 120 character line'''
    ips        = r.hget('Domain:'+str(sublist), 'ip')
    first      = r.hget('Domain:'+str(sublist), 'first')
    date       = r.hget('Domain:'+str(sublist), 'date')
    rr_type    = r.hget('Domain:'+str(sublist), 'type')
    ttl        = r.hget('Domain:'+str(sublist), 'ttl')
    count      = r.hget('Domain:'+str(sublist), 'count')
    if first == None:
        first = '00000000'
    if date == None:
        date = '00000000'

    #FINAL PRINT
    print "{0:40} {1:15} {2:9} {3:9} {4:5} {5:5} {6:9}".format(sublist,ips,first[:8],date[:8],record_translate(rr_type),ttl,count)
    
    # add below if vaulable
    #dns_client = r.hget('Domain:'+str(sublist), 'dns_client')
    #dns_server = r.hget('Domain:'+str(sublist), 'dns_server')
    #print dns_client,",",sublist,",",dns_server,",",dns_server
    pass	


# =====================================

def header_ip():
    # header for IP based print information
    print  "{0:18} {1:35} {2:9} {3:9} {4:8} {5:8} {6:6} ".format ("IP","query","first","date","rr","ttl","count")
    pass


def ip_print(sublist):
    query      = r.hget('IP:'+str(sublist), 'name')
    first      = r.hget('IP:'+str(sublist), 'first')
    date       = r.hget('IP:'+str(sublist), 'date')
    count      = r.hget('IP:'+str(sublist), 'count')
    rr_type    = r.hget('IP:'+str(sublist), 'type')
    ttl        = r.hget('IP:'+str(sublist), 'ttl')
    count      = r.hget('IP:'+str(sublist), 'count')
    #dns_client = r.hget(sublist, 'dns_client')
    #dns_server = r.hget(sublist, 'dns_server')
    #nss        = r.hget(sublist, 'nss')

    if first == None:
        first = '00000000'
    if date == None:
        date = '00000000'
    
    # PRINT FIELDS
    print "{0:18} {1:35} {2:9} {3:9} {4:8} {5:8} {6:6}".format(sublist,query,first[:8],date[:8],record_translate(rr_type),ttl,count)
    pass

def key_stripper(fullkey):
    ''' this fuction takes the right side of any ':' split and returns as a list '''
    newset = []
    for each in fullkey:
        subset = each.split(':')
        subset1 = subset[1]
        newset.append(subset1)
    return(newset)

def Domain_sort(fqdn):
    ''' sort domains by ending zone  '''
    fulldata = []
    for each in fqdn:
        fulldata.append(each[::-1])
    fulldata.sort()  
    fixdata = []
    for each in fulldata:
        fixdata.append(each[::-1]) 
    return(fixdata)

def domain_counter(fqdn):
    ''' counter for domains based on the last two zones '''
    fulldata = []
    for each in fqdn:
        a = count((each),".")
        if a >= 2:
            fulldata.append(each[::-1])
    fulldata.sort()
    domain_trunk = []
    for each in fulldata:
        splitdata = each.split('.')
        # treat the first two as one
        TwoZones = str(splitdata[0])+"."+str(splitdata[1])
        #print TwoZones
        domain_trunk.append(TwoZones)        
    fulldata = []
    for each in domain_trunk:
        fulldata.append(each[::-1])
    return (Counter(fulldata))

def dtg_local():
    ''' simplified datetime stripped to YYYYMMDD based on current '''
    dtg = time.localtime()
    if dtg.tm_mon < 10:
        mon_fix = str('0')+str(dtg.tm_mon)
    else:
        mon_fix = str(dtg.tm_mon)
    return str(dtg.tm_year)+mon_fix+str(dtg.tm_mday)

def dqn_to_int(st):
    ''' 127.0.0.1 => 2130706433 '''
    st = st.split(".")
    return int("%02x%02x%02x%02x" % (int(st[0]),int(st[1]),int(st[2]),int(st[3])),16)

def int_to_dqn(st):
    ''' convert string to IP address 2130706433 => 127.0.0.1  '''
    st = "%08x" % (st)
    return "%i.%i.%i.%i" % (int(st[0:2],16),int(st[2:4],16),int(st[4:6],16),int(st[6:8],16))

class pdns():
    ''' a database query libarary for pdns.
    pass a string in single quotes '''
    def domain(self, domain):
        domain_list = r.keys('Domain:'+domain)
        worklist = key_stripper(domain_list)
        worklist1 = Domain_sort(worklist)
        print header_dom()
        for sublist in worklist1:
            dom_print(sublist)

    def ip(self, ip):
        ''' query by ip address '''
        ip_list = r.keys('IP:'+str(ip))                     
        worklist = key_stripper(ip_list)               
        worklist.sort()                                
        print header_ip()                              
        for each in worklist:
            ip_print(each)                             

    def date(self, date):
        '''query by date in format ('20130101')'''
        match_hold = []
        domain_list = r.keys("Domain:*")
        print domain_list
        for sublist in domain_list:
            datecheck = r.hget(sublist, 'date')
            if datecheck != None:
                if datecheck[:8] == date:
                    match_hold.append(sublist)
        match_hold1 = key_stripper(match_hold)
        match_hold2 = Domain_sort(match_hold1)
        print header_dom()
        for each in match_hold2:
            dom_print(each)

    def ttl(self, ttl):
        ''' search all domains for specific ttl and below, not that useful but interesting'''
        match_hold = []
        print 'Returning DOMAINS where TTL is equel or less than:',ttl
        domain_list = r.keys("Domain:*")
        for sublist in domain_list:
            ttlcheck = r.hget(sublist, 'ttl')
            if ttlcheck != None and int(ttlcheck) <= int(ttl):
                   match_hold.append(sublist)        
        match_hold1 = key_stripper(match_hold)
        match_hold2 = Domain_sort(match_hold1)
        print header_dom()
        for each in match_hold2:
            dom_print(each)

    def rrecord(self, domain):
        ''' submit a domain query and return only record by type
         data encoded in the payload might use Base32/Base64 Binary, NetBios, or Hex encoding. 
         A records to CNAME, to MX and TXT records, can be combined with EDNS, increasing payload size.
         (TXT records are the most common because they offer the largest and most diverse payload structure.) '''
        match_hold = []
        print 'Returning txt records for',domain
        domain_list = r.keys("Domain:"+domain)
        for sublist in domain_list:
            ttlcheck = r.hget(sublist, 'type')
            if ttlcheck == '0x0010':
                   match_hold.append(sublist)        
        match_hold1 = key_stripper(match_hold)
        match_hold2 = Domain_sort(match_hold1) # revise sort to be the records
        print header_dom()
        for each in match_hold2:
            dom_print(each)

    def local(self):
        ''' searches for local resolution such as 127.0.0.1 '''
        ip_hit = []
        alldom = r.keys('Domain:*.*')
        first_oct = '127.'
        for each in alldom:
            ips = r.hget(each, 'ip')
            if ips != None:
                #print ips, ips[:4], first_oct
                if ips[:4] == first_oct:               
                    ip_hit.append(each)
                if ips[:7] == '169.254.':
                    ip_hit.append(each)
        worklist = key_stripper(ip_hit)          
        worklist1 = Domain_sort(worklist)        
        print header_dom()                       
        for sublist in worklist1:
            dom_print(sublist)        

    def acount(self, domain):
        ''' counts of counts, or 'hits' for the domains in order, *.google.com or *.com are examples '''
        alldom = r.keys('Domain:'+str(domain)) 
        allcount = []
        for each in alldom:
            acount = r.hget(each, 'count')  
            if acount == None:
                pass
            else:
                allcount.append([int(acount),each]) 
        allcount.sort()
        for each in allcount:
            print str(each[0]),str(each[1]) 

    def ip_flux(self, arg1):
        ''' Search IP space for a count of domains '''
        all_ips = r.keys('IP:'+str(arg1))
        allcount = []
        for each in all_ips:
            acount = r.hget(each, 'name') # working list
            #print acount
            if acount == None:
                pass
            else:
                allcount.append(acount)
        x = Counter(allcount).most_common(50)
        for k in x:
            print u'{0}'.format(k)
    
    def ip_reverse(self, ip, domain):
        ''' search a given IP space for each instance of a domain
        generally useful with ip_flux '''
        print 'using IP',ip,'domain', domain
        print 'current mapped domain below'
        dom_print(domain)
        all_ips = r.keys('IP:'+str(ip))
        print header_ip()
        for each in all_ips:
            work_domain = r.hget(each, 'name')
            if work_domain == domain:
                ip_print(each[3:])
    
    def dom_unanswered(self, arg1,arg2):
        ''' find unaswered name request for searched domain space
        MX record are excluded
        format 'domain.com', min count'''
        all_dom = r.keys('Domain:'+str(arg1))
        print header_dom()
        for each in all_dom:
            work_ip = r.hget(each, 'ip')
            if work_ip == '':
                record = r.hget(each, 'type')
                count = r.hget(each, 'count')
                if record != '0x000f' and record != '0x0006' and int(count) >= arg2:
                    dom_print(each[7:])
        
    
    def count(self, domain):
        ''' count the subdomains within a ROOT domains ('domain.com') '''
        alldom = r.keys('Domain:'+str(domain))
        # call domain_counter function
        x = domain_counter(alldom).most_common(500)
        for k, v in x:
            print u'{0}: {1}'.format(k, v)

    def ip_sniff(self, ip):
        ''' search domain space for a given IP address ('1.1.1.1') '''
        #enumerates the domain space for IP address (not domain)
        match_hold = []
        domain_list = r.keys('Domain:*')        # KEY RETRIEVAL 
        print 'all keys pulled, checking for', ip
        for each in domain_list:
            testkey = r.hget(each, 'ip')
            #print testkey, query
            if testkey == ip:
                print each
                match_hold.append(each)
        worklist = key_stripper(match_hold) 
        worklist1 = Domain_sort(worklist) 
        print header_dom() 
        for sublist in worklist1: 
            dom_print(sublist)
    
    def raw_record(self, arg1):
        hold = r.hgetall(arg1)
        print hold
    
    def help(self):
        print 'pDNS2 commands\n'
        print 'DOMAIN EXAMPLES'
        print 'domain(\'*xstamper.com\') seeks all domains that end with xstamper.com'
        print 'ttl(\'0\')                use a number like 0 or 100 to get all the TTL of a specific value search is based on domain not IP'
        print 'count(\'*\')             return by query,count sub domains for a given domain example: .cn .com .google.com '
        print 'acount(\'*\')            return by query, counts of counts (usage), or \'hits\' for the domains in order, *.google.com or *.com are examples '
        print ''
        print 'IP EXAMPLES'
        print 'ip(\'222.*\')            returns 222.* or anything '
        print 'local()                  search entire database local resolved IP addresses that resolve to 127.0.0.1 etc. '
        print 'ip_flux(\'*.com\')       return a COUNT of domains in the IP space for each instance of a domain, use with ip_reverse'
        print 'x.ip_reverse(\'*\',\'seattletimes.com\') use with ip_flux, enumerate domains in the IP space'
        print ''
        print 'TAGGING'
        print 'tag_domain(\'ms.justice.cz\')    tag a domain'
        print 'tag_ip(\'194.213.41.92\')        tag an IP address '
        print ''        
        print 'THREAT DETECTION'
        print 'ip_sniff(\'192.168.1.1\')    search the domain space for a specific IP address, different then searching by IP '
        print 'date(\'20130101\')           return all records by date'

        print ''
        print 'ADMINISTRATIVE'
        print 'delete_key(\'Domain:*delete*\') Dangerous command, deletes a key, must use the entire key such as Domain: or IP:'
        print 'raw_record(\'Domain:xalrbngb-0.t.nessus.org\') view the raw record properties (no wildcards) use full key name'
        print 'pDNS2 tracks current state and last known, it is a snapshot of organization perception, not a log.'


# REDIS CONNECTION 
r = redis.StrictRedis(host='localhost', port=6379, db=2)
x = pdns()


usable = ['domain','ip','date','ip_sniff','ttl','rrecord','local','acount','count','ip_flux','ip_reverse']

def main():
    parser = argparse.ArgumentParser(description='pDNS2 a tool to collect and store DNS request and responses. Requires Redis server running on default port.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-d','--domain')#, nargs=1
    group.add_argument('-i','--ip')
    parser.add_argument('-date','--date')
    parser.add_argument('-ips','--ip_sniff')
    parser.add_argument('-ttl','--ttl')
    parser.add_argument('-rr','--rrecord')
    parser.add_argument('-l','--local', action='store_true')
    parser.add_argument('-ac','--acount')
    parser.add_argument('-c','--count')
    parser.add_argument('-ipf','--ip_flux')
    parser.add_argument('-ipr','--ip_reverse', nargs=2)
    #group.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    #print args.domain
    if args.domain != None:
        x.domain(args.domain)
    elif args.ip != None:
        x.ip(args.ip)
    elif args.date != None:
        x.date(args.date)
    elif args.ip_sniff != None:
        x.ip_sniff(args.ip_sniff)
    elif args.ttl != None:
        x.ttl(args.ttl)
    elif args.rrecord != None:
        x.rrecord(args.rrecord)
    elif args.local != None:
        x.acount(args.local)
    elif args.count != None:
        x.count(args.count)
    elif args.ip_flux != None:
        x.ip_flux(args.ip_flux)
    elif args.ip_reverse != None:
        x.ip_reverse(args.ip_reverse[0],args.ip_reverse[1])
    else:
        x.help()
    sys.exit(-1)



if __name__ == '__main__':
    main()
