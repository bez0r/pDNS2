pDNS2
=====

pDNS2 project

pDNS2 is yet another implementation of a passive DNS tool working with Redis as the database. pDNS2 means ‘passive DNS version2’ and favors speed in query over other database features.
pDNS2 is based on Florian Weimer’s original dnslogger with improved features for speed and specialization for analyst.


REQUIREMENTS
------------

Redis http://redis.io/
Redis API https://github.com/andymccurdy/redis-py
wireshark full install http://www.wireshark.org/




GETTING STARTED
---------------

This version has two simple python scripts to support the collection of DNS traffic as pdns2_collect.py and the other to query as pdns2_query.py

1. Ensure wireshare’s share is working and can collect on the desired interface or read pcap files.
2. Run redis-server and listening on local port 6379
3. run pdns2_collect.py with -i for an interface or -p for a pcap file
4. Anytime the collection is working, try pdns2_query.py with the options available.

below are are simply using a wildcard with -d for any domain

Sample query
python pdns2_query.py -d *


>  Domain                                   ips             first     date      rr    ttl   count    
  w2.eff.org                               69.50.232.52    20120524  20120524  CNAME 300   3        
  web5.eff.org                             69.50.232.52    20120524  20120524  A     300   3        
  slashdot.org                             216.34.181.45   20120524  20120524  A     2278  1        
  csi.gstatic.com                          74.125.143.120  20120524  20120524  A     300   1        
  ssl.gstatic.com                          74.125.229.175  20120524  20120524  A     244   1        
  xkcd.com                                 107.6.106.82    20120524  20120524  A     600   1        
  imgs.xkcd.com                            69.9.191.19     20120524  20120524  CNAME 418   1        
  www.xkcd.com                             107.6.106.82    20120524  20120524  CNAME 600   1        
  craphound.com                            204.11.50.137   20120524  20120524  A     861   1        
  www.youtube.com                          173.194.37.4    20120524  20120524  CNAME 81588 1        
<

AUTHOR
------

pDNS is developed and maintained 
terraplex at gmail.com


