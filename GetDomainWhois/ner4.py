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
from top_whois_server_config import TLDs  #获得顶级域名域名WHOIS服务器列表
from gevent import monkey;monkey.patch_all()

THREADNUM = 6

try:
    conn=MySQLdb.Connection(host='172.26.253.3',user='root',passwd='platform',db='cyn_malicious_domain',charset='utf8')
except:
    print 'connect db failer'
    sys.exit()

cursor = conn.cursor()


def extract_domain(url = ''):
    """
    提取网址中的域名,e.g.，http://www.baidu.com/index.html，提取出www.baidu.com
    """

    if not url:
        print 'The url is empty'
        sys.exit()

    domain = ''

    #添加http头部
    scheme = re.compile("https?\:\/\/", re.IGNORECASE)
    if scheme.match(url) is None:
        url = "http://" + url

    parsed = urlparse(url)   #urlparse格式化
    domain = parsed.netloc   #提取域名
    
    if not domain:               
        print 'Wrong url format'
        sys.exit()  #空则结束

    return domain



class domain_info:
    """
    域名信息类，包括网址、域名、WHOIS服务器等信息
    """

    def __init__(self,url=''):

        self.url = url      
        self.domain = ''
        self.query_domain = ''
        self.top_whois_server = ''      #顶级WHOIS服务器
        self.sec_whois_server = ''      #二级WHOIS服务器
        self.real_sec_whois_server = '' #真实查询WHOIS服务器
        self.reg_name = ''              #注册姓名
        self.reg_phone = ''             #注册电话
        self.reg_email = ''             #注册邮箱         

        self.domain = extract_domain(self.url) #提取域名
        self.achieve_top_whois_server()        #获得顶级WHOIS服务器


    def achieve_top_whois_server(self):
        """
        根据顶级域名WHOIS信息注册商列表，获得顶级WHOIS服务器
        """
    
        PointSplitResult = self.domain.split('.')
        domain_length = len(PointSplitResult)
        top_level_domain = '.' + PointSplitResult[-1]
        
        if domain_length <= 2:
            if TLDs.has_key(top_level_domain.lower()):
                self.top_whois_server = TLDs[top_level_domain.lower()]
                self.query_domain = self.domain
            else:
                print "没有该顶级域名WHOIS注册商，请联系管理员"
                sys.exit()

        second_level_domain = '.' + PointSplitResult[-2]
        host = second_level_domain + top_level_domain 
      
        if TLDs.has_key(host.lower().strip()):    
            self.top_whois_server = TLDs[host.lower()]
            self.query_domain = PointSplitResult[-3] + host.lower()

        elif TLDs.has_key(top_level_domain.lower()):
            self.top_whois_server = TLDs[top_level_domain.lower()]
            self.query_domain = PointSplitResult[-2] + top_level_domain.lower()

        else:
            print '没有该顶级域名WHOIS注册商，请联系管理员'
            sys.exit()


    def domain_whois(self):
        """
        获得二级域名WHOIS信息注册商信息
        """
        sec_whois_server = ''

        if str(self.top_whois_server) == "['whois.verisign-grs.com', 'whois.crsnic.net']":
            sec_whois_server = self.com_net_manage()
            if sec_whois_server == 'xxx':
                print '运行到xxx'
                self.xxx_manage()
            if sec_whois_server == 'Done':
                print '第一层结束'
                return

            self.achieve_whois_info()

        elif str(self.top_whois_server) == "['whois.nic.me', 'whois.meregistry.net']":
            self.me_manage()

        elif str(self.top_whois_server) == "whois.ua":
            self.ua_manage()

        elif str(self.top_whois_server) == "['whois.iedr.ie', 'whois.domainregistry.ie']":
            self.ie_manage()

        elif str(self.top_whois_server) == "['whois.pir.org', 'whois.publicinterestregistry.net']":
            self.org_manage()

        elif str(self.top_whois_server) == "whois.ripe.net":
            self.es_manage()

        elif str(self.top_whois_server) == "['whois.ripn.ru', 'whois.ripn.net']":
            self.ru_manage()
        elif str(self.top_whois_server) == "['whois.afilias.info', 'whois.afilias.net']":
            self.info_manage()


    def com_net_manage(self):
        """
        .com,.net为顶级域名的WHOIS服务器处理
        """

        data_result = ''
        data_result = self.get_socket('top',True)

        if not data_result:
            print '没有数据返回'
            sys.exit()

        if self.achieve_whois_info(flag=False,data_result=data_result) :   #在顶级域名注册商已经包含所有注册消息
            return 'Done'

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
                        print 'Something Wrong'
                        sys.exit()
        elif match_other:
            return match_other.group()
        else:
            print 'other'
            sys.exit()


    def xxx_manage(self):
        """
        处理在.com,.net域名中，包含xxx的情形
        """

        data_result = ''
        data_result = self.get_socket('top',False)   #顶级域名，加标志位'='
        print data_result

        pattern = re.compile(r'Domain Name:.*|Whois Server:.*')  
        match = pattern.findall(data_result)                   #查找符合条件内容
        
        if match:
            length = len(match)
            for i in range(length):
                
                if match[i].lower().find(self.query_domain) != -1:

                    try:
                        self.sec_whois_server= match[i+1].split(':')[1].strip()
                        break
                    except:
                        print '出错，检查'
                        sys.exit()


    def me_manage(self):

        data_result = ''
        data_result = self.get_socket('top',True)

        if not data_result:
            print '没有数据返回'
            sys.exit()

        if self.achieve_whois_info(flag=False,data_result=data_result) :   #在顶级域名注册商已经包含所有注册消息
            return 'Done'

    
    def achieve_whois_info(self, flag=True,data_result=''):

        if flag:

            data_result = self.get_socket('second')
        
        if not data_result:
            print 'nothing in second result'
            sys.exit()

        pattern = re.compile(r'(Domain Name:.*|Registrant Phone:.*|Registrant Name:.*|Registrant Email.*|Registrant E-mail:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        if match_length == 4:

            print match
            self.reg_name = match[1].split(':')[1].strip()
            self.reg_phone = match[2].split(':')[1].strip()
            self.reg_email = match[3].split(':')[1].strip()
            return True


    def ua_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        pattern = re.compile(r'(person:.*|e-mail:.*|phone:.*)')
        match = pattern.findall(data_result)
        print match
        # print len(match)
        count = len(match)
        self.reg_name = match[count-3].split(':')[1].strip()
        self.reg_phone = match[count-1].split(':')[1].strip()
        self.reg_email = match[count-2].split(':')[1].strip()
        return True


    def ie_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        pattern = re.compile(r'(person:.*)')
        match = pattern.findall(data_result)
        print match
        count = len(match)
        self.reg_name = match[0].split(':')[1].strip()
        return True

    def org_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        pattern = re.compile(r'(Domain Name:.*|Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        print match
        if match_length == 4:

            print match
            self.reg_name = match[1].split(':')[1].strip()
            self.reg_phone = match[2].split(':')[1].strip()
            self.reg_email = match[3].split(':')[1].strip()
            return True


    def es_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        pattern = re.compile(r'(org-name:.*|abuse-mailbox:.*|phone:.*)')
        match = pattern.findall(data_result)
        print match
        count = len(match)
        self.reg_name = match[0].split(':')[1].strip()
        self.reg_email = match[1].split(':')[1].strip()
        self.reg_phone = match[2].split(':')[1].strip()
        return True

    def ru_manage(self):
        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        pattern = re.compile(r'(person:.*)')
        match = pattern.findall(data_result)
        print match
        count = len(match)
        self.reg_name = match[0].split(':')[1].strip()

    def info_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        pattern = re.compile(r'(Domain Name:.*|Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        print match
        if match_length == 4:

            print match
            self.reg_name = match[1].split(':')[1].strip()
            self.reg_phone = match[2].split(':')[1].strip()
            self.reg_email = match[3].split(':')[1].strip()
            return True

    def get_socket(self,level='',flag=True):
        """
        与域名WHOIS信息注册商进行连接查询,level表示顶级或者二级查询，flag表示是否需要添加"="标志
        """

        #flag标志位
        if flag:
            query_domain = self.query_domain  #无flag
        
        else:
            query_domain = '=' + self.query_domain #有'='

        #顶级、二级域名查询
        if level == 'top':
            if type(self.top_whois_server) == list:    #若WHOIS注册商为列表，则随机选择一个
                HOST = choice(self.top_whois_server)
            
            else:
                HOST = self.top_whois_server
        elif level == 'second':
            HOST = self.sec_whois_server

        data_result = ''
        PORT = 43
        BUFSIZ = 1024
        ADDR = (HOST, PORT)
        EOF = "\r\n"
        data_send = query_domain + EOF

        try:
            tcpCliSock = socket(AF_INET, SOCK_STREAM)
            tcpCliSock.settimeout(10)
            tcpCliSock.connect(ADDR)
            tcpCliSock.send(data_send)
        except:
            print 'Socket Wrong'
            sys.exit()

        while True:

            try:
                data_rcv = tcpCliSock.recv(BUFSIZ)
            except:
                print 'receive Failed'
                tcpCliSock.close()
                sys.exit()

            if not len(data_rcv):
                tcpCliSock.close()
                # print data_result
                return data_result  #返回查询结果
            data_result = data_result + data_rcv


def get_domain():

    sql_input = 'SELECT domain FROM whois_info '
    cursor.execute(sql_input)
    domain_tuple = cursor.fetchall()
    domain_list = [extract_domain(i[0]) for i in domain_tuple]

    sql_haved = 'SELECT domain FROM whois_info_copy_copy'
    cursor.execute(sql_haved)
    domain_haved = cursor.fetchall()
    domain_list_haved = [i[0] for i in domain_haved]
    
    return list(set(domain_list).difference(set(domain_list_haved)))


def check_domain(url=''):


    data_result = ''
    query_domain = domain_info(url)
    # query_domain.achieve_second_whois_server()
    query_domain.domain_whois()

    sql = "INSERT ignore INTO  whois_info_copy_copy (domain,top_whois_server,sec_whois_server,reg_name,reg_phone,reg_email) VALUES( %s,%s,%s,%s,%s,%s)"
    cursor.execute(sql,(query_domain.domain,str(query_domain.top_whois_server),query_domain.sec_whois_server,query_domain.reg_name,query_domain.reg_phone,query_domain.reg_email))
    conn.commit()


def main():

    domain_list = []
    domain_list = get_domain()

    total_domain_count = len(domain_list)
    count = 0
    print total_domain_count
    while count * THREADNUM < total_domain_count:
        domains = domain_list[count * THREADNUM : (count + 1) * THREADNUM]
        gevent.joinall([gevent.spawn(check_domain, str(domain.strip())) for domain in domains])
        count = count + 1
    conn.close()


if __name__ == '__main__':
    main()
