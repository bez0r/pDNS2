#!/usr/bin/env python

# Database tool to interact with pDNS2, query a populated Redis database
# this version works well
import datetime
import time

# needed for counting function
from string import count
from collections import Counter
import redis  # https://github.com/andymccurdy/redis-py


# http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
# http://en.wikipedia.org/wiki/List_of_DNS_record_types
RRECORD_TO_RRTYPE = {
    '0x0001': 'A', # a host address
    '0x0002': 'NS', # a name server
    '0x0005': 'CNAME', # cononical name
    '0x000f': 'MX', # mail exchange, should only work with a mail exchange, isolate this type of DNS from host
    '0x0006': 'SOA', # start of a zone authority
    '0x000c': 'PTR', # name pointer
    '0x0010': 'TXT', # watch this one, because it supports 189 bytes per record, sometime an exfil channel
    '0x001c': 'AAAA', # ipv6
    '0x0029': 'OPT', # optional (used with DNSSEC)
    '0x002e': 'RRSIG', # resource register digital signature
    '0x0021': 'SRV', # server selection
    '0x002f': 'NSEC', # authenticated denial of existence
    '0x0032': 'NSEC3', # authenticated denial of existenc v3?
    '0x002b': 'DS', # delegation signer
    '0x00fa': 'TSIG', # transaction security mechanisms
}

def record_translate(rrecord):
    '''Resolves records by type'''
    return RRECORD_TO_RRTYPE.get(rrecord, 'unknown')



def header_dom():
    ''' header and linked to domain searched output'''
    print "{0:40} {1:15} {2:9} {3:9} {4:5} {5:5} {6:8} {7:10} {8:8} {9:8} {10:9} {11:12}".format ("Domain","ips","first","date","rr","ttl","count","threat","date","tag","source","dom")
    pass

def dom_print(sublist):
    ''' print the queried list in a 120 character line'''
    # sublist as passed contains the 'Domain:' with the search criteria
    ips        = r.hget('Domain:'+str(sublist), 'ip')
    first      = r.hget('Domain:'+str(sublist), 'first')
    date       = r.hget('Domain:'+str(sublist), 'date')
    rr_type    = r.hget('Domain:'+str(sublist), 'type')
    ttl        = r.hget('Domain:'+str(sublist), 'ttl')
    count      = r.hget('Domain:'+str(sublist), 'count')
    # access the TDOM keys
    threat    = r.hget('TDOM:'+str(sublist), 'threat')
    evaldate  = r.hget('TDOM:'+str(sublist), 'evaldate')
    tag       = r.hget('TDOM:'+str(sublist), 'tag')
    source    = r.hget('TDOM:'+str(sublist), 'source')   
    # check the subsequent key TIP if tagged as threat
    ips_hit   = r.hget('TIP:'+str(ips), 'threat')
    # fix strings for dates
    if first == None:
        first = '00000000'
    if date == None:
        date = '00000000'

    #FINAL PRINT
    print "{0:40} {1:15} {2:9} {3:9} {4:5} {5:5} {6:9} {7:10} {8:8} {9:8} {10:8} {11:12}".format(sublist,ips,first[:8],date[:8],record_translate(rr_type),ttl,count,threat, evaldate,tag,source,ips_hit)
    # denoting DNS client and server is sometime useful, depeends on the organization
    
    #dns_client = r.hget('Domain:'+str(sublist), 'dns_client')
    #dns_server = r.hget('Domain:'+str(sublist), 'dns_server')
    #print dns_client,",",sublist,",",dns_server,",",dns_server
    pass	


# =====================================

def header_ip():
    # header for IP based print information
    print  "{0:18} {1:35} {2:9} {3:9} {4:8} {5:8} {6:6} {7:12} {8:8} {9:12} {10:10} {11:12}".format ("IP","query","first","date","rr","ttl","count","threat","date","tag","source","dom")
    pass


def ip_print(sublist):
    # split and remove the header before you get here along with sort
    # BASIC DNS / IP PROPERTIES
    query      = r.hget('IP:'+str(sublist), 'name')
    first      = r.hget('IP:'+str(sublist), 'first')
    date       = r.hget('IP:'+str(sublist), 'date')
    count      = r.hget('IP:'+str(sublist), 'count')
    rr_type    = r.hget('IP:'+str(sublist), 'type')
    ttl        = r.hget('IP:'+str(sublist), 'ttl')
    count      = r.hget('IP:'+str(sublist), 'count')
    threat      = r.hget('TIP:'+str(sublist), 'threat')
    evaldate   = r.hget('TIP:'+str(sublist), 'evaldate')
    tag       = r.hget('TIP:'+str(sublist), 'tag')
    source    = r.hget('TIP:'+str(sublist), 'source')
    dom_hit   = r.hget('TDOM:'+str(query), 'threat')

    ## below fields have value in some networks, you decide if you want to dispay it
    #dns_client = r.hget(sublist, 'dns_client')
    #dns_server = r.hget(sublist, 'dns_server')
    #nss        = r.hget(sublist, 'nss')

    
    # fix strings for dates
    if first == None:
        first = '00000000'
    if date == None:
        date = '00000000'
    
    
    # PRINT FIELDS
    print "{0:18} {1:35} {2:9} {3:9} {4:8} {5:8} {6:6} {7:12} {8:8} {9:12} {10:10} {11:12}".format(sublist,query,first[:8],date[:8],record_translate(rr_type),ttl,count,threat,evaldate,tag,source,dom_hit)
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
    for each in fqdn:           #reverse the order
        fulldata.append(each[::-1])
    fulldata.sort()     # sort based on reversed order
    fixdata = []
    for each in fulldata:
        fixdata.append(each[::-1])          #now that it is sorted, reverse and return it
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
    ''' simplified datetime stripped to YYYYMMDD based on NOW '''
    dtg = time.localtime()
    if dtg.tm_mon < 10:
        mon_fix = str('0')+str(dtg.tm_mon)
    else:
        mon_fix = str(dtg.tm_mon)
    if dtg.tm_mday < 10:
        day_fix = str('0')+str(dtg.tm_mday)
    else:
        day_fix = str(dtg.tm_mday)
    return str(dtg.tm_year)+mon_fix+str(day_fix)


def dqn_to_int(st):
    ''' 127.0.0.1 => 2130706433 '''
    st = st.split(".")
    return int("%02x%02x%02x%02x" % (int(st[0]),int(st[1]),int(st[2]),int(st[3])),16)

def int_to_dqn(st):
    ''' convert string to IP address 2130706433 => 127.0.0.1  '''
    st = "%08x" % (st)
    return "%i.%i.%i.%i" % (int(st[0:2],16),int(st[2:4],16),int(st[4:6],16),int(st[6:8],16))

def knn_ip(ip_data,factor):
    '''for ip_data produce a list of adds to search based on factor '''
    ''' this needs a bit of work to ensure the function is used correctly'''
    ip_worklist = []
    factor1 = int(factor)
    for each in ip_data:
        a = each.split(':')
        b = dqn_to_int(a[1])
        for n in range(b-factor1,b+factor1,1):
            convert = int_to_dqn(n)
            testvalue = str('IP:'+str(convert))
            ip_worklist.append(testvalue)
    return(ip_worklist)

class pdns():
    ''' a database query libarary for pdns.
    pass a string in single quotes '''
    def domain(self, domain):
        domain_list = r.keys('Domain:'+domain)
        tdom_list = r.keys('TDOM:'+domain)
        domain_list.extend(tdom_list)
        worklist = key_stripper(domain_list)
        worklist1 = Domain_sort(worklist)
        print header_dom()
        for sublist in worklist1:
            dom_print(sublist)

    def ip(self, ip):
        ''' query by ip address '''
        ip_list = r.keys('IP:'+ip)
        tip_list = r.keys('TIP:'+ip)
        ip_list.extend(tip_list)                       
        worklist = key_stripper(ip_list)               
        worklist.sort()                                
        print header_ip()                              
        for each in worklist:
            ip_print(each)                             

    def date(self, date):
        '''query by date in format ('20130101')'''
        match_hold = []
        domain_list = r.keys("Domain:*")
        for sublist in domain_list:
            datecheck = r.hget(sublist, 'date')
            if datecheck != None:
                if datecheck[:8] == date:
                    match_hold.append(sublist)
        match_hold1 = key_stripper(match_hold)
        print 'made it here'
        match_hold2 = Domain_sort(match_hold1)
        print header_dom()
        for each in match_hold2:
            dom_print(each)

    def first(self, date):
        '''query by date in format ('20130101') for first seen'''
        match_hold = []
        domain_list = r.keys("Domain:*")
        for sublist in domain_list:
            datecheck = r.hget(sublist, 'first')
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
    



    def knn(self,ip,knn_ip):
        '''The threat IP addresses only to locate nearby active IP addresses
        requires a number such as 20 '''
        threatip = r.keys('TIP:'+str(ip))
        threatip.sort()
        for each in threatip:
            trusttest1 = r.hget(each, 'tag')
            trusttest2 = r.hget(each, 'threat')
            if trusttest1 == 'trusted' or trusttest2 == 'trusted':
                threatip.remove(each)
                
        match_hold = ip_knn(threatip,knn_ip)
        knn_printlist = []
        for each in match_hold:
            queryname = r.hget(each, 'name')
            if queryname != None:
                knn_printlist.append(each)
        worklist = key_stripper(knn_printlist)
        for each in worklist:
            ip_print(each)


    def tip(self, tip_ip):
            #TIP raw output
        threatip = r.keys('TIP:'+tip_ip)
        for each in threatip:
            threat    = r.hget(each, 'threat')
            evaldate  = r.hget(each, 'evaldate')
            tag       = r.hget(each, 'tag')
            source    = r.hget(each, 'source')
            print '{},{},{},{},{}'.format(each,threat,evaldate,tag,source)

    def tdom(self, tdom_domain):
        # TDOM raw output
        threatdom = r.keys('TDOM:'+tdom_domain)
        for each in threatdom:
            threat    = r.hget(each, 'threat')
            evaldate  = r.hget(each, 'evaldate')
            tag       = r.hget(each, 'tag')
            source    = r.hget(each, 'source')
            print '{},{},{},{},{}'.format(each,threat,evaldate,tag,source)

    def local(self):
        ''' searches for local resolution such as 127.0.0.1 '''
        ip_hit = []
        alldom = r.keys('Domain:*.*')
        first_oct = '127.'
        for each in alldom:
            ips = r.hget(each, 'ip')
            if ips != None:
                #print ips, ips[:4], first_oct
                if ips[:4] == first_oct:                # match any 127.* but does not include 169.254.
                    ip_hit.append(each)
                if ips[:7] == '169.254.':
                    ip_hit.append(each)
        worklist = key_stripper(ip_hit)           # strip the key
        worklist1 = Domain_sort(worklist)         # use the domain sort function here (reversed by zone)
        print header_dom()                        # sort before you pass to print (domain requires special sort)
        for sublist in worklist1:
            dom_print(sublist)        

    def acount(self, domain):
        ''' counts of counts, or 'hits' for the domains in order, *.google.com or *.com are examples '''
        alldom = r.keys('Domain:'+str(domain)) #summary of counts for any given domain(includes subdomains) within the search key provided
        allcount = []
        for each in alldom:
            acount = r.hget(each, 'count')  # retrieve only the count, no other field is needed at this time
            if acount == None:
                pass
            else:
                allcount.append([int(acount),each]) #
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
        # consider an exclusion list
        # locate mass number of sub domains
        # REVERSE OF IP will resolve only a single domain, not all domains that have the same pairing
        # remember a change over time is more valuable then instant stats
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
        worklist = key_stripper(match_hold) # call KEY STRIPPER FUNCTION
        worklist1 = Domain_sort(worklist) # use the domain sort function here (reversed by zone)
        print header_dom() # sort before you pass to print (domain requires special sort)
        for sublist in worklist1: # enumerate the list with a loop
            dom_print(sublist) # print it out

    def tag_domain(self, domain):
        ''' tag a domain as trusted, possible threat, or threat '''
        print r.hgetall('Domain:'+str(domain))
        print r.hgetall('TDOM:'+str(domain))

        alignment = good_vs_evil()
        date_time = dtg_local()
        tag = pdns2tag()
        source = pdns2source()
        print 'Appending a threat description to',domain

        r.hset('TDOM:'+str(domain), 'threat', alignment)
        r.hset('TDOM:'+str(domain), 'evaldate', date_time)
        r.hset('TDOM:'+str(domain), 'tag', tag)
        r.hset('TDOM:'+str(domain), 'source', source)
        # simple print preview at the end
        print r.hgetall('Domain:'+str(domain))
        print r.hgetall('TDOM:'+str(domain))

    def tag_ip(self, ip):
        ''' apply a threat rating to IP '''
        print r.hgetall('IP:'+str(ip))
        print r.hgetall('TIP:'+str(ip))
        alignment = good_vs_evil()
        date_time = dtg_local()
        tag = pdns2tag()
        source = pdns2source()
        r.hset('TIP:'+str(ip), 'threat', alignment)
        r.hset('TIP:'+str(ip), 'evaldate', date_time)
        r.hset('TIP:'+str(ip), 'tag', tag)
        r.hset('TIP:'+str(ip), 'source', source)
        print r.hgetall('IP:'+str(ip))
        print r.hgetall('TIP:'+str(ip))
    
    def delete_key(self, arg1):
        ''' delete any key from the pdns2 database
        must use the full key name such as:
        Domain:delete.me.com
        IP:1.1.1.1
        TIP:1.1.1.1
        TDOM:bad.domain.com '''
        domain_list = r.keys(arg1)
        if len(domain_list) == 0 or arg1 == '*':
            print 'no keys found or dangerous key selection'
            pass
        print 'about to DETELE ',len(domain_list),' keys.'
        key_review = raw_input('Would you like to see the keys? (y/n)')
        if key_review == 'y':
            for each in domain_list:
                print(each)        
        default_source = raw_input('Are you sure you want to delete the above keys (y/n)?')
        if default_source == 'y':
            for each in domain_list:
                r.delete(each)
            print 'completed'
        else:
            print 'aborting'
        pass
    
    def raw_record(self, arg1):
        hold = r.hgetall(arg1)
        print hold
    
    def help(self):
        print 'pDNS2 commands\n'
        print 'DOMAIN EXAMPLES'
        print 'domain(\'*xstamper.com\') seeks all domains that end with xstamper.com'
        print 'ttl(\'0\')                use a number like 0 or 100 to get all the TTL of a specific value search is based on domain not IP'
        print 'tdom(\'*\')              return by query, tagged domain threats '
        print 'count(\'*\')             return by query,count sub domains for a given domain example: .cn .com .google.com '
        print 'acount(\'*\')            return by query, counts of counts (usage), or \'hits\' for the domains in order, *.google.com or *.com are examples '
        print ''
        print 'IP EXAMPLES'
        print 'ip(\'222.*\')            returns 222.* or anything '
        print 'tip(\'192.168.*\')       return by query, tagged IP addresses'
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
        print 'knn_dom(\'*.google.com\',20)  DO NOT USE IN DEV, returns euclidian distance threats by IP address '

        print ''
        print 'ADMINISTRATIVE'
        print 'delete_key(\'Domain:*delete*\') Dangerous command, deletes a key, must use the entire key such as Domain: or IP:'
        print 'raw_record(\'Domain:xalrbngb-0.t.nessus.org\') view the raw record properties (no wildcards) use full key name'
        print 'dom_unanswered(\'*.com\',1000) return unanswered queries by minimual count such as everything in .com with 1000 or more'
        print 'threat(5)                    search threats by provided date (DO NOT USE, work in progress)\n'        
        print 'pDNS2 tracks current state and last known, it is a snapshot of organization perception, not a log.'
        
        #x.rrecord('*')

def good_vs_evil():
    #determine = ['t','p','c','s']
    alignment = 'possible threat'
    print 't=trusted, p=possible threat, c=confirmed threat, default POSSIBLE THREAT'
    align = raw_input('threat tag:')
    print align
    if align == 't':
        alignment = 'trusted'
        return alignment
    elif align == 'p':
        alignment = 'possible threat'
        return alignment
    elif align == 'c':
        alignment = 'confirmed threat'
        return alignment
    else:
        alignment = 'possible threat'
    return alignment

def pdns2tag():
    tags_base = ['scan','phish','spam','malware','c2','dynamicDNS','commercial','victim','policy']
    print tags_base
    result = False
    while result == False:
        desired_tag = raw_input('input tag:')
        if desired_tag in tags_base:
            result = True
            return desired_tag
    else:
        pass

def pdns2source():
    source = 'no attrib'
    print 'no attrib is default, others might be threatexpert urlvoid'
    default_source = raw_input('source tag:')
    if default_source == '':
        return source
    else:
        return default_source




# REDIS CONNECTION MANAGEMENT
'''open a connection to the local redis database'''
# Default pDNS database is set to 2 and should remain so
r = redis.StrictRedis(host='localhost', port=6379, db=2)


x = pdns()
##  examples and tests uncomment and test with your data
#x.domain(‘*example*’)
#x.ip('200.*’)
#x.date('20140613')  
#x.ttl('0') 
#x.tip('192.168.*')  # pass the ip  192.168.*
#x.tdom('*')   # pass a domain to see if in the threat list
#x.local()   #walk the entire database in search of any domains that resolve to 127.0.0.1 etc.



