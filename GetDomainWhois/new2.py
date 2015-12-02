#!/usr/bin/python
#encoding:utf-8

import re
import sys
import MySQLdb
import urllib2
import gevent
from socket import *
from random import choice
from urlparse import urlparse
from top_whois_server_config import TLDs
from gevent import monkey;monkey.patch_all()


THREADNUM = 6

try:
    conn=MySQLdb.Connection(host='172.26.253.3',user='root',passwd='platform',db='cyn_malicious_domain',charset='utf8')
except:
    print 'connect db failer'
    sys.exit()

cursor = conn.cursor()

def extract_domain(url = ''):

    if not url:
        print 'The url is empty'
        sys.exit()

    
    domain = ''
    scheme = re.compile("https?\:\/\/", re.IGNORECASE)
    if scheme.match(url) is None:
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain:
        print 'Wrong url format'
        sys.exit()

    return domain

class domain_info:

    def __init__(self,url=''):

        self.url = url
        self.domain = ''
        self.query_domain = ''
        self.top_whois_server = ''
        self.sec_whois_server = ''
        self.real_sec_whois_server = ''
        self.reg_name = ''
        self.reg_phone = ''
        self.reg_email = ''
        self.level = 'second'
        self.domain = extract_domain(self.url)
        
        self.achieve_top_whois_server()


    def extract_domain(self):

        if not self.url:
            print 'The url is empty'
            sys.exit()

        url = ''
        domain = ''
        scheme = re.compile("https?\:\/\/", re.IGNORECASE)
        if scheme.match(self.url) is None:
            url = "http://" + self.url
        else:
            url = self.url

        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            print 'Wrong url format'
            sys.exit()
        self.domain = domain


    def achieve_top_whois_server(self):
        
        PointSplitResult = self.domain.split('.')
        

        top_level_domain = '.' + PointSplitResult[-1]

        try:
            second_level_domain = '.' + PointSplitResult[-2]
        except:
            second_level_domain = ''

        host = second_level_domain + top_level_domain 
      
        if TLDs.has_key(host.lower().strip()):
            
            self.top_whois_server = TLDs[host.lower()]
            self.query_domain = PointSplitResult[-3] + host.lower()

        elif TLDs.has_key(top_level_domain.lower()):
            
            self.top_whois_server = TLDs[top_level_domain.lower()]
            self.query_domain = PointSplitResult[-2] + top_level_domain.lower()

        else:
            print 'There is not this whois_server'
            sys.exit()


    def achieve_second_whois_server(self,flag=True):

        data_result = ''
        data_result = self.get_socket('top',flag)
        
        print data_result
        if not data_result:
            print 'nothing in second result'
            sys.exit()

        pattern = re.compile(r'Domain Name:.*|Whois Server:.*')
        match = pattern.findall(data_result)
        pattern_other = re.compile(r'xxx')
        match_other = pattern_other.search(data_result)
        
        if match:
            length = len(match)
            for i in range(length):
                
                if match[i].lower().find(self.query_domain) != -1:
                    try:
                        self.sec_whois_server= match[i+1].split(':')[1].strip()
                    except:
                        # self.achieve_whois_info('top')
                        self.level = 'top'
                        # print 'ndindkj'

        elif match_other:

            print match_other.group()
            self.achieve_second_whois_server(False)

        else:
            print 'other'
            sys.exit()


    def achieve_whois_info(self,level='second'):

        data_result = ''
        level = self.level
        data_result = self.get_socket(level)
        if not data_result:
            print 'nothing in second result'
            sys.exit()

        pattern = re.compile(r'(Domain Name:.*|Registrant Phone:.*|Registrant Name:.*|Registrant Email.*)')
        match = pattern.findall(data_result)
        if match:

            print match
            self.reg_name = match[1].split(':')[1].strip()
            self.reg_phone = match[2].split(':')[1].strip()
            self.reg_email = match[3].split(':')[1].strip()

        # domain_whois[0].split(':')[1].strip(),str(top_whois_server),sec_whois_server,domain_whois[1].split(':')[1].strip(),domain_whois[2].split(':')[1].strip(),domain_whois[3].split(':')[1].strip()))



    def get_socket(self,level='',flag=True):


        if level == 'top':
            if flag:
                query_domain = self.query_domain
            else:
                query_domain = '=' + self.query_domain
            
            if type(self.top_whois_server) == list: #If the server are lists,random choose one.
                HOST = choice(self.top_whois_server)
            else:
                HOST = self.top_whois_server

        elif level == 'second':

            query_domain = self.query_domain
            HOST = self.sec_whois_server

        else:
            print 'wrong'
            sys.exit()

        data_result = ''
        PORT = 43
        BUFSIZ = 1024
        ADDR = (HOST, PORT)
        EOF = "\r\n"
        data_send = query_domain + EOF

        try:
            tcpCliSock = socket(AF_INET, SOCK_STREAM)
            tcpCliSock.settimeout(5)
        except socket.error, msg:
            print 'Failed to create socket. Error code:' + str(msg[0]) + ', Error message:' + msg[1]
            sys.exit()
        try:
            tcpCliSock.connect(ADDR)
        except:
            print 'Error connecting to server'
            sys.exit()

        try:

            tcpCliSock.send(data_send)
        except socket.error:
            print 'Send Failed'
            sys.exit()

        while True:
                
            try:
                data_rcv = tcpCliSock.recv(BUFSIZ)
            except:
                print 'receive Failed'
                tcpCliSock.close()
                sys.exit()

            if not len(data_rcv):
                return data_result
            data_result = data_result + data_rcv

        tcpCliSock.close()



def check_domain(url=''):

    data_result = ''
    query_domain = domain_info(url)
    query_domain.achieve_second_whois_server()
    query_domain.achieve_whois_info()

    sql = "INSERT ignore INTO  whois_info_copy (domain,top_whois_server,sec_whois_server,reg_name,reg_phone,reg_email) VALUES( %s,%s,%s,%s,%s,%s)"
    cursor.execute(sql,(query_domain.domain,str(query_domain.top_whois_server),query_domain.sec_whois_server,query_domain.reg_name,query_domain.reg_phone,query_domain.reg_email))
    conn.commit()


def get_domain():

    sql_input = 'SELECT domain FROM whois_info WHERE (top_whois_server is NULL or top_whois_server="")'
    cursor.execute(sql_input)
    domain_tuple = cursor.fetchall()
    
    domain_list = [extract_domain(i[0]) for i in domain_tuple]
    # print domain_list
    # print len(domain_list)
    # domain_list = list(set(domain_list))
    
    # print len(domain_list)
    sql_haved = 'SELECT domain FROM whois_info_copy'
    cursor.execute(sql_haved)
    domain_haved = cursor.fetchall()
    domain_list_haved = [i[0] for i in domain_haved]
    
    return list(set(domain_list).difference(set(domain_list_haved)))
    
def main():

    domain_list = []
    domain_list = get_domain()

    total_domain_count = len(domain_list)
    count = 0


    while count * THREADNUM < total_domain_count:
        domains = domain_list[count * THREADNUM : (count + 1) * THREADNUM]
        gevent.joinall([gevent.spawn(check_domain, str(domain.strip())) for domain in domains])
        count = count + 1
    conn.close()


if __name__ == '__main__':
    main()
