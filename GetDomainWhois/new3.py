#!/usr/bin/python
# encoding:utf-8

import re
import sys
import MySQLdb
from socket import *
from urlparse import urlparse
from random import choice
from gevent import monkey;monkey.patch_all()
import gevent

try:
    conn=MySQLdb.Connection(host='172.26.253.3',user='root',passwd='platform',db='cyn_malicious_domain',charset='utf8')
except:
    print 'connect db failer'
    sys.exit()

cursor = conn.cursor()
THREADNUM = 2

TLDs = {
    ".com":  ["whois.verisign-grs.com","whois.crsnic.net"],
    ".net":  ["whois.verisign-grs.com","whois.crsnic.net"],
    ".org":  ["whois.pir.org", "whois.publicinterestregistry.net"],
    ".info":  ["whois.afilias.info", "whois.afilias.net"],
    ".biz":  "whois.neulevel.biz",
    ".us":  "whois.nic.us",
    ".uk":  "whois.nic.uk",
    ".ca":  "whois.cira.ca",
    ".tel":  "whois.nic.tel",
    ".ie":  ["whois.iedr.ie", "whois.domainregistry.ie"],
    ".it":  "whois.nic.it",
    ".li":  "whois.nic.li",
    ".no":  "whois.norid.no",
    ".cc":  "whois.nic.cc",
    ".eu":  "whois.eu",
    ".nu":  "whois.nic.nu",
    ".au":  ["whois.aunic.net", "whois.ausregistry.net.au"],
    ".de":  "whois.denic.de",
    ".ws":  ["whois.worldsite.ws", "whois.nic.ws", "www.nic.ws"],
    ".sc":  "whois2.afilias-grs.net",
    ".mobi":  "whois.dotmobiregistry.net",
    ".pro":  ["whois.registrypro.pro", "whois.registry.pro"],
    ".edu":  ["whois.educause.net", "whois.crsnic.net"],
    ".tv":  ["whois.nic.tv", "tvwhois.verisign-grs.com"],
    ".travel":  "whois.nic.travel",
    ".name":  "whois.nic.name",
    ".in":  ["whois.inregistry.net", "whois.registry.in"],
    ".me":  ["whois.nic.me", "whois.meregistry.net"],
    ".at":  "whois.nic.at",
    ".be":  "whois.dns.be",
    ".cn":  ["whois.cnnic.cn", "whois.cnnic.net.cn"],
    # ".edu.cn": "whois.edu.cn",
    ".asia":  "whois.nic.asia",
    ".ru":  ["whois.ripn.ru", "whois.ripn.net"],
    ".ro":  "whois.rotld.ro",
    ".aero":  "whois.aero",
    ".fr":  "whois.nic.fr",
    ".se":  ["whois.iis.se", "whois.nic-se.se", "whois.nic.se"],
    ".nl":  ["whois.sidn.nl", "whois.domain-registry.nl"],
    ".nz":  ["whois.srs.net.nz", "whois.domainz.net.nz"],
    ".mx":  "whois.nic.mx",
    ".tw":  ["whois.apnic.net", "whois.twnic.net.tw"],
    # ".tw": "whois.twnic.net.tw",
    ".ch":  "whois.nic.ch",
    ".hk":  "whois.hknic.net.hk",
    ".ac":  "whois.nic.ac",
    ".ae":  "whois.nic.ae",
    ".af":  "whois.nic.af",
    ".ag":  "whois.nic.ag",
    ".al":  "whois.ripe.net",
    ".am":  "whois.amnic.net",
    ".as":  "whois.nic.as",
    ".az":  "whois.ripe.net",
    ".ba":  "whois.ripe.net",
    ".bg":  "whois.register.bg",
    ".bi":  "whois.nic.bi",
    ".bj":  "www.nic.bj",
    ".br":  "whois.nic.br",
    ".br.com": "whois.centralnic.net",
    ".eu.org": "whois.eu.org",
    ".bt":  "whois.netnames.net",
    ".by":  "whois.ripe.net",
    ".bz":  "whois.belizenic.bz",
    ".cd":  "whois.nic.cd",
    ".ck":  "whois.nic.ck",
    ".cl":  "whois.nic.cl",
    ".coop":  "whois.nic.coop",
    ".cx":  "whois.nic.cx",
    ".cy":  "whois.ripe.net",
    ".cz":  "whois.nic.cz",
    ".dk":  "whois.dk-hostmaster.dk",
    ".dm":  "whois.nic.cx",
    ".dz":  "whois.ripe.net",
    ".ee":  "whois.eenet.ee",
    ".eg":  "whois.ripe.net",
    ".es":  "whois.ripe.net",
    ".fi":  "whois.ficora.fi",
    ".fo":  "whois.ripe.net",
    ".gb":  "whois.ripe.net",
    ".ge":  "whois.ripe.net",
    ".gl":  "whois.ripe.net",
    ".gm":  "whois.ripe.net",
    ".gov":  "whois.nic.gov",
    ".gr":  "whois.ripe.net",
    ".gs":  "whois.adamsnames.tc",
    ".hm":  "whois.registry.hm",
    ".hn":  "whois2.afilias-grs.net",
    ".hr":  "whois.ripe.net",
    ".hu":  "whois.ripe.net",
    ".il":  "whois.isoc.org.il",
    ".int":  "whois.isi.edu",
    ".iq":  "vrx.net",
    ".ir":  "whois.nic.ir",
    ".is":  "whois.isnic.is",
    ".je":  "whois.je",
    ".jp":  "whois.jprs.jp",
    ".kg":  "whois.domain.kg",
    ".kr":  "whois.nic.or.kr",
    ".la":  "whois2.afilias-grs.net",
    ".lt":  "whois.domreg.lt",
    ".lu":  "whois.restena.lu",
    ".lv":  "whois.nic.lv",
    ".ly":  "whois.lydomains.com",
    ".ma":  "whois.iam.net.ma",
    ".mc":  "whois.ripe.net",
    ".md":  "whois.nic.md",
    ".mil":  "whois.nic.mil",
    ".mk":  "whois.ripe.net",
    ".ms":  "whois.nic.ms",
    ".mt":  "whois.ripe.net",
    ".mu":  "whois.nic.mu",
    ".my":  "whois.mynic.net.my",
    ".nf":  "whois.nic.cx",
    ".pl":  "whois.dns.pl",
    ".pr":  "whois.nic.pr",
    ".pt":  "whois.dns.pt",
    ".sa":  "saudinic.net.sa",
    ".sb":  "whois.nic.net.sb",
    ".sg":  "whois.nic.net.sg",
    ".sh":  "whois.nic.sh",
    ".si":  "whois.arnes.si",
    ".sk":  "whois.sk-nic.sk",
    ".sm":  "whois.ripe.net",
    ".st":  "whois.nic.st",
    ".su":  "whois.ripn.net",
    ".tc":  "whois.adamsnames.tc",
    ".tf":  "whois.nic.tf",
    ".th":  "whois.thnic.net",
    ".tj":  "whois.nic.tj",
    ".tk":  "whois.nic.tk",
    ".tl":  "whois.domains.tl",
    ".tm":  "whois.nic.tm",
    ".tn":  "whois.ripe.net",
    ".to":  "whois.tonic.to",
    ".tp":  "whois.domains.tl",
    ".tr":  "whois.nic.tr",
    ".ua":  "whois.ripe.net",
    ".uy":  "nic.uy",
    ".uz":  "whois.cctld.uz",
    ".va":  "whois.ripe.net",
    ".vc":  "whois2.afilias-grs.net",
    ".ve":  "whois.nic.ve",
    ".vg":  "whois.adamsnames.tc",
    ".yu":  "whois.ripe.net",

}

def extract_url_domain(url=''):

    if not url:
        print 'The url is empty'
        return


    scheme = re.compile("https?\:\/\/", re.IGNORECASE)
    if scheme.match(url) is None:
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain:
        print 'wrong url format'
        return
    return domain


def select_top_whois_server(url=''):

    if not url:
        print 'empty url'
        return

    domain = ''
    domain = extract_url_domain(url)
    PointSplitResult = domain.split('.')
    last_host = '.' + PointSplitResult[-1]
    last_but_one_host = '.' + PointSplitResult[-2]

    host = last_but_one_host + last_host
    if TLDs.has_key(host.lower()):
        print TLDs[host.lower()]
        return TLDs[host.lower()], PointSplitResult[-3] + host

    elif TLDs.has_key(last_host.lower()):
        print TLDs[last_host.lower()]
        
        return TLDs[last_host.lower()],PointSplitResult[-2] + last_host
    else:
        print 'There is not this whois_server'
        return


def get_socket(HOST='',domain=''):


    if type(HOST) == list: #If the server are lists,random choose one.
        HOST = choice(HOST)

    print HOST
    print domain

    PORT = 43
    BUFSIZ = 1024
    ADDR = (HOST, PORT)
    EOF = "\r\n"
    data_send = domain + EOF

    try:
        tcpCliSock = socket(AF_INET, SOCK_STREAM)
        tcpCliSock.settimeout(5)
    except socket.error, msg:
        print 'Failed to create socket. Error code:' + str(msg[0]) + ', Error message:' + msg[1]
        # sys.exit()
        return
    try:
        tcpCliSock.connect(ADDR)
    except:
        print 'Error connecting to server'
        # sys.exit()
        return
    try:

        tcpCliSock.send(data_send)
    except socket.error:
        print 'Send Failed'
        # sys.exit()
        return

    data_result = ''

    while True:
        
        try:
            data_rcv = tcpCliSock.recv(BUFSIZ)
        except:
            print 'receive Failed'
            tcpCliSock.close()
            # sys.exit()
            return

        if not len(data_rcv):
            print data_result
            tcpCliSock.close()
            return data_result
        data_result = data_result + data_rcv

        print data_rcv
    tcpCliSock.close()


def extract_sec_whois_server(data_result='',domain=''):

    if not data_result:
        print 'second whois server data_result is empty'
        # sys.exit()
        return

    pattern = re.compile(r'Domain Name:.*|Whois Server:.*')
    pattern_other = re.compile(r'xxx')
    match = pattern.findall(data_result)

    length = len(match)
    if match:
        # print match
        for i in range(length):
            # print match[i]
            if match[i].lower().find(domain) != -1:
                print match[i+1]
                return match[i+1][14:]

    else:
        match_other = pattern_other.search(data_result)
        if match_other:
            return match_other.group()
        return


def extract_whois_info(data_result):

    if not data_result:
        return
    pattern = re.compile(r'(Registrant Phone:.*|Registrant Name:.*|Registrant Email.*)')
    match = pattern.findall(data_result)
    if match:
        print match
    return



def get_whois(domain=''):

    print domain
    data_result = ''
    query_domain = ''
    top_whois_server = ''
    sec_whoi_server = ''
    # url = 'www.baidu.com'
    top_whois_server,query_domain = select_top_whois_server(domain)
    data_result = get_socket(top_whois_server,query_domain)
    # print data_result
    sec_whoi_server = extract_sec_whois_server(data_result,query_domain)
    if sec_whoi_server == 'xxx':
        data_result = get_socket(top_whois_server,'='+query_domain)
        # print data_result
        sec_whoi_server = extract_sec_whois_server(data_result,query_domain)
        data_result = get_socket(sec_whoi_server,query_domain)
        # print data_result
        extract_whois_info(data_result)
    
    # print sec_whoi_server
    else:
        data_result = get_socket(sec_whoi_server,query_domain)
        print data_result
        extract_whois_info(data_result)




def main():


    url = 'www.travistio.ie'
    url = 'revolvecreative.ie'
    url = 'www.specialchild.ie'
    url = 'a79717bw.bget.ru'
    url = 'aguacomunicaciones.cl'
    get_whois(url)
    # get_socket('whois.tcinet.ru',url)

if __name__ == '__main__':
    main()