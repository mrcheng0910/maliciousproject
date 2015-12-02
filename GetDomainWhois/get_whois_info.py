#!/usr/bin/python
# encoding:utf-8

import re
import sys
import MySQLdb
import urllib2
import gevent
import time
from socket import *
from random import choice
from urlparse import urlparse
from top_whois_server_config import TLDs  # 获得顶级域名域名WHOIS服务器列表
from gevent import monkey
monkey.patch_all()

THREADNUM = 6

try:
    conn = MySQLdb.Connection(host='172.26.253.3', user='root',
                              passwd='platform', db='cyn_malicious_domain', charset='utf8')
except:
    print 'connect db failer'
    sys.exit()

cursor = conn.cursor()


def extract_domain(url=''):
    """
    提取网址中的域名,e.g.，http://www.baidu.com/index.html，提取出www.baidu.com
    """

    if not url:
        print 'The url is empty'
        # sys.exit()
        return

    domain = ''

    # 添加http头部
    scheme = re.compile("https?\:\/\/", re.IGNORECASE)
    if scheme.match(url) is None:
        url = "http://" + url

    parsed = urlparse(url)  # urlparse格式化
    domain = parsed.netloc  # 提取域名

    if not domain:
        print 'Wrong url format'
        # sys.exit()  # 空则结束
        return

    return domain


class domain_info:

    """
    域名信息类，包括网址、域名、WHOIS服务器等信息
    """

    def __init__(self, url=''):

        self.url = url
        self.domain = ''
        self.query_domain = ''
        self.top_whois_server = ''  # 顶级WHOIS服务器
        self.sec_whois_server = ''  # 二级WHOIS服务器
        self.real_sec_whois_server = ''  # 真实查询WHOIS服务器
        self.reg_name = ''  # 注册姓名
        self.reg_phone = ''  # 注册电话
        self.reg_email = ''  # 注册邮箱

        self.domain = extract_domain(self.url)  # 提取域名
        self.achieve_top_whois_server()  # 获得顶级WHOIS服务器

    def achieve_top_whois_server(self):
        """
        根据顶级域名WHOIS信息注册商列表，获得顶级WHOIS服务器
        """
        if not self.domain:
            return

        PointSplitResult = self.domain.split('.')
        domain_length = len(PointSplitResult)
        top_level_domain = '.' + PointSplitResult[-1]

        if domain_length <= 2:
            if TLDs.has_key(top_level_domain.lower()):
                self.top_whois_server = TLDs[top_level_domain.lower()]
                self.query_domain = self.domain
            else:
                print "没有该顶级域名WHOIS注册商，请联系管理员"
                return

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
            # sys.exit()
            return

    def domain_whois(self):
        """
        获得二级域名WHOIS信息注册商信息
        """

        if str(self.top_whois_server) == "['whois.verisign-grs.com', 'whois.crsnic.net']":
            self.com_net_manage()

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

        elif str(self.top_whois_server)== "whois.nic.us":
            self.us_manage()

        elif str(self.top_whois_server) == "['whois.cnnic.cn', 'whois.cnnic.net.cn']":
            self.cn_manage()

        elif str(self.top_whois_server)== 'whois.nic.uk':
            self.uk_manage()

        elif str(self.top_whois_server) == "whois.adamsnames.tc":
            self.tc_manage()

        elif str(self.top_whois_server) == "whois.twnic.net.tw":
            self.query_domain = self.domain
            self.tw_manage()
        
        elif str(self.top_whois_server) == "whois.rotld.ro":
            self.ro_manage()
        
        elif str(self.top_whois_server) == "['whois.registrypro.pro', 'whois.registry.pro']":
            self.pro_manage()

        elif str(self.top_whois_server) == "['whois.inregistry.net', 'whois.registry.in']":
            self.in_manage()

        elif str(self.top_whois_server) == 'whois.eu':
            self.eu_manage()

        elif str(self.top_whois_server) == 'whois.nic.xyz':
            self.org_manage()
        
        elif str(self.top_whois_server) == "whois.aeda.net.ae":
            self.ae_manage()

        elif str(self.top_whois_server) == "whois.nic.tr":
            self.tr_manage()
        
        elif str(self.top_whois_server) == "whois.cira.ca":
            self.ca_manage()
        
        elif str(self.top_whois_server) == "['whois.srs.net.nz', 'whois.domainz.net.nz']":
            self.nz_manage()
        
        elif str(self.top_whois_server) == "whois.denic.de":
            self.nz_manage()

        elif str(self.top_whois_server) == "whois.dns.pl":
            self.pl_manage()
        elif str(self.top_whois_server) == "whois.nic.it":
            self.it_manage()

        elif str(self.top_whois_server) == "whois.amnic.net":
            self.am_manage()

        elif str(self.top_whois_server)== "whois.neulevel.biz":
            self.biz_manage()

        elif str(self.top_whois_server) == "whois.dotmobiregistry.net":
            self.mobi_manage()
        
        elif str(self.top_whois_server) == "whois.nic.as":
            self.as_manage()
        elif str(self.top_whois_server) == "whois.nic.es":
            self.es_manage()
        elif str(self.top_whois_server) == "whois.nic.br":
            self.br_manage()

        elif str(self.top_whois_server) == "whois.nic.cl":
            self.cl_manage()
        
        else:
            return

    def com_net_manage(self):
        """
        .com,.net为顶级域名的WHOIS服务器处理
        """

        data_result = ''
        data_result = self.get_socket('top', True)

        if not data_result:
            print '没有数据返回'
            return

        i = 0
        pattern = re.compile(
            r'(Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
        match_top = pattern.findall(data_result)
        match_length = len(match_top)

        

        if match_top:
            for i in range(match_length):
                if match[i].split(':')[0].strip() == 'Registrant Phone':
                    self.reg_phone = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Name':
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Email':
                    self.reg_email = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant E-mail':
                    self.reg_email = match[i].split(':')[1].strip()
            return

        pattern = re.compile(r'Domain Name:.*|Whois Server:.*')
        match = pattern.findall(data_result)

        if match:
            length = len(match)
            for i in range(length):

                if match[i].lower().find(self.query_domain) != -1:

                    try:
                        self.sec_whois_server = match[i + 1].split(':')[1].strip()
                        self.achieve_whois_info()
                        return
                    except:
                        print 'Something Wrong'
                        sys.exit()


        pattern_other = re.compile(r'xxx')
        match_other = pattern_other.search(data_result)

        if match_other:
            self.xxx_manage()
            return

        pattern_no = re.compile(r'No match')
        match = pattern_no.search(data_result)
        if match:
            print 'NoMatch'
            self.reg_name = 'NoMatch'
            return

    def xxx_manage(self):
        """
        处理在.com,.net域名中，包含xxx的情形
        """

        data_result = ''
        data_result = self.get_socket('top', False)  # 顶级域名，加标志位'='
        # print data_result

        pattern = re.compile(r'Domain Name:.*|Whois Server:.*')
        match = pattern.findall(data_result)  # 查找符合条件内容

        if match:
            length = len(match)
            for i in range(length):

                if match[i].lower().find(self.query_domain) != -1:

                    try:
                        self.sec_whois_server = match[
                            i + 1].split(':')[1].strip()
                        self.achieve_whois_info(flag=True)
                        break
                    except:
                        print '出错，检查'
                        sys.exit()

    def achieve_whois_info(self, flag=True, data_result=''):

        if flag:

            data_result = self.get_socket('second')

        if not data_result:
            print 'nothing in second result'
            return

        pattern = re.compile(
            r'(Domain Name:.*|Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        print match

        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'Registrant Phone':
                self.reg_phone = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Name':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Email':
                self.reg_email = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant E-mail':
                self.reg_email = match[i].split(':')[1].strip()
        

    def me_manage(self):

        data_result = ''
        data_result = self.get_socket('top', True)

        if not data_result:
            print '没有数据返回'
            sys.exit()

        # 在顶级域名注册商已经包含所有注册消息
        if self.achieve_whois_info(flag=False, data_result=data_result):
            return 

    def ua_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return
        pattern = re.compile(r'(person:.*|e-mail:.*|phone:.*)')
        match = pattern.findall(data_result)
        print match
        # print len(match)
        count = len(match)
        self.reg_name = match[count - 3].split(':')[1].strip()
        self.reg_phone = match[count - 1].split(':')[1].strip()
        self.reg_email = match[count - 2].split(':')[1].strip()

    def ie_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return
        # print data_result
        pattern = re.compile(r'(person:.*)')
        match = pattern.findall(data_result)
        print match
        count = len(match)
        self.reg_name = match[0].split(':')[1].strip()
        
    def org_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return
        pattern = re.compile(
            r'(Domain Name:.*|Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        print match

        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'Registrant Phone':
                self.reg_phone = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Name':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Email':
                self.reg_email = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant E-mail':
                self.reg_email = match[i].split(':')[1].strip()

    def es_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        # print data_result
        if not data_result:
            return
        pattern = re.compile(r'(org-name:.*|abuse-mailbox:.*|phone:.*)')
        match = pattern.findall(data_result)
        print match
        count = len(match)

        for i in range(count):

            if match[i].split(':')[0].strip() == 'org-name':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'abuse-mailbox':
                self.reg_email = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'phone':
                self.reg_phone = match[i].split(':')[1].strip()


    def ru_manage(self):
        data_result = ''
        data_result = self.get_socket('top')
        # print data_result
        if not data_result:
            return
        pattern = re.compile(r'(person:.*|registrar:.*)')
        match = pattern.findall(data_result)
        print match
        if match:
            self.reg_name = match[0].split(':')[1].strip()

    def info_manage(self):

        i = 0
        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return
        pattern = re.compile(r'(Domain Name:.*|Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        print match

        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'Registrant Phone':
                self.reg_phone = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Name':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Email':
                self.reg_email = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant E-mail':
                self.reg_email = match[i].split(':')[1].strip()
        return

    def us_manage(self):

        i = 0
        data_result = ''
        data_result = self.get_socket('top')
        
        if not data_result:
            return

        pattern = re.compile(r'(Domain Name:.*|Registrant Phone Number:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        
        print match
        
        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'Registrant Phone Number':
                self.reg_phone = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Name':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Email':
                self.reg_email = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant E-mail':
                self.reg_email = match[i].split(':')[1].strip()

    def cn_manage(self):

        i = 0
        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return
        pattern = re.compile(r'(Registrant Phone Number:.*|Registrant:.*|Registrant Contact Email:.*)')
        match = pattern.findall(data_result)
        match_length = len(match)
        
        print match





        
        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'Registrant Phone Number':
                self.reg_phone = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
                self.reg_email = match[i].split(':')[1].strip() 

    def uk_manage(self):

        i = 0
        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return
        pattern = re.compile(r"(Registrant's address:\s\s.*\s\s.*)")
        match = pattern.findall(data_result)
        match_length = len(match)
        print match
        
        
        for i in range(match_length):
            if match[i].split(':')[0].strip() == "Registrant's address":
                self.reg_name = match[i].split(':')[1].strip().replace('\r\n      ',' ') 

    def tc_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return

        pattern = re.compile(r'(Domain Name:.*|Registrant Name:.*|Registrant Email:.*|Registrant Phone:.*)')
        match = pattern.findall(data_result)
        print match
        count = len(match)

        for i in range(count):

            if match[i].split(':')[0].strip() == 'Registrant Name':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Email':
                self.reg_email = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Phone':
                self.reg_phone = match[i].split(':')[1].strip()

    def tw_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        if not data_result:
            return

        pattern = re.compile(r'(Registrant:\s.*|TEL:.*)')
        
        match = pattern.findall(data_result)
        print match
        count = len(match)

        for i in range(count):
            
            if match[i].split(':')[0].strip() == 'Registrant':
                self.reg_name = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'TEL':
                self.reg_phone = match[i].split(':')[1].strip()

        pattern_em = re.compile(r'(.*@.*)')
        match = pattern_em.findall(data_result)
        if match:
            self.reg_email = match[0] 

    def ro_manage(self):
        

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Domain Name:.*|Registrar:.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)

            for i in range(count):

                if match[i].split(':')[0].strip() == 'Registrar':
                    self.reg_name = match[i].split(':')[1].strip()
        else:
            print 'get _socket data_result None' 

    def pro_manage(self):
        print 'in_manage'
        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Domain Name:.*|Registrant Name:.*|Registrant Phone:.*|Registrant Email:.*)')
            match = pattern.findall(data_result)
            print 'match::',match
            count = len(match)

            for i in range(count):

                if match[i].split(':')[0].strip() == 'Registrant Name':
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Phone':
                    self.reg_phone = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Email':
                    self.reg_email = match[i].split(':')[1].strip()
        else:
            print 'get _socket data_result None' 

    def in_manage(self):
        print 'in_manage'
        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Domain Name:.*|Registrant Name:.*|Registrant Email:.*|Registrant Phone:.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)

            for i in range(count):

                if match[i].split(':')[0].strip() == 'Registrant Name':
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Email':
                    self.reg_email = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Phone':
                    self.reg_phone = match[i].split(':')[1].strip()
        else:
            print 'get _socket data_result None'

    def eu_manage(self):

        self.reg_name = 'NOT DISCLOSED'

    def ae_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Registrant Contact Name:.*|Registrant Contact Email:.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)

            for i in range(count):

                if match[i].split(':')[0].strip() == 'Registrant Contact Name':
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
                    self.reg_email = match[i].split(':')[1].strip()
        else:
            print 'get _socket data_result None'

    def tr_manage(self):
        
        self.reg_name = "Nothing"

    def ca_manage(self):

        
        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'Registrar:\n.+Name:(.*)')
            match = pattern.findall(data_result)
            count = len(match)
            if count==1:
                self.reg_name = match[0].strip()
                print 'self.reg_name::',self.reg_name
            else:
                print 'match::',match
        else:
            print 'get _socket data_result None' 

    def nz_manage(self):
        self.reg_name = "Nothing"

    def pl_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(REGISTRAR:\s\s.*|\+.*|.*@.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)

            for i in range(count):

                if match[i].find('REGISTRAR:') >= 0:
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].find('+') >=0 :
                    self.reg_phone = match[i].strip()
                elif match[i].find('@') >=0 :
                    self.reg_email = match[i].strip()
        else:
            print 'get _socket data_result None' 

    def it_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Name:.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)
            self.reg_name = match[0].split(':')[1].strip()

        else:
            print 'get _socket data_result None'  

    def am_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Administrative contact:\s\s.*|\+.*|.*@.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)

            for i in range(count):

                if match[i].find('Administrative contact:') >= 0:
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].find('+') >=0 :
                    self.reg_phone = match[i].strip()
                elif match[i].find('@') >=0 :
                    self.reg_email = match[i].strip()
        else:
            print 'get _socket data_result None' 

    def biz_manage(self):
        print 'in_manage'
        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Registrant Name:.*|Registrant Email:.*|Registrant Phone Number:.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)

            for i in range(count):

                if match[i].split(':')[0].strip() == 'Registrant Name':
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Email':
                    self.reg_email = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Phone Number':
                    self.reg_phone = match[i].split(':')[1].strip()
        else:
            print 'get _socket data_result None'

    def mobi_manage(self):

        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Registrant Name:.*|Registrant Email:.*|Registrant Phone:.*)')
            match = pattern.findall(data_result)
            print match
            count = len(match)

            for i in range(count):

                if match[i].split(':')[0].strip() == 'Registrant Name':
                    self.reg_name = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Email':
                    self.reg_email = match[i].split(':')[1].strip()
                elif match[i].split(':')[0].strip() == 'Registrant Phone':
                    self.reg_phone = match[i].split(':')[1].strip()
        else:
            print 'get _socket data_result None' 

    def as_manage(self):
        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Registrar:\s\s.*)')
            match = pattern.findall(data_result)
            print match
            self.reg_name = match[0]

        else:
            print 'get _socket data_result None'

    def es_manage(self):

        self.reg_name = 'NoMatch'
    def br_manage(self):
        self.reg_name = 'NoMatch'

    def cl_manage(self):
        
        data_result = ''
        data_result = self.get_socket('top')
        print data_result
        if data_result:
            pattern = re.compile(r'(Nombre.*)')
            match = pattern.findall(data_result)
            print match
            
            self.reg_name = match[0].split(':')[1].strip()
        else:
            print 'get _socket data_result None'

    def get_socket(self, level='', flag=True):
        """
        与域名WHOIS信息注册商进行连接查询,level表示顶级或者二级查询，flag表示是否需要添加"="标志
        """

        # flag标志位
        if flag:
            query_domain = self.query_domain  # 无flag

        else:
            query_domain = '=' + self.query_domain  # 有'='

        # 顶级、二级域名查询
        if level == 'top':
            if type(self.top_whois_server) == list:  # 若WHOIS注册商为列表，则随机选择一个
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
            tcpCliSock.settimeout(8)
            tcpCliSock.connect(ADDR)
            tcpCliSock.send(data_send)
        except:
            print 'Socket Wrong'
            return

        while True:

            try:
                data_rcv = tcpCliSock.recv(BUFSIZ)
            except:
                print 'receive Failed'
                tcpCliSock.close()
                return

            if not len(data_rcv):
                tcpCliSock.close()

                # print data_result
                return data_result  # 返回查询结果
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

    
    query_domain = domain_info(url)
    # query_domain.achieve_second_whois_server()
    query_domain.domain_whois()
    
    if not query_domain.query_domain:
        return

    sql = "INSERT ignore INTO  whois_info_copy_copy (domain,top_whois_server,sec_whois_server,reg_name,reg_phone,reg_email) VALUES( %s,%s,%s,%s,%s,%s)"
    cursor.execute(sql, (query_domain.domain, str(query_domain.top_whois_server),
                         query_domain.sec_whois_server, query_domain.reg_name, query_domain.reg_phone, query_domain.reg_email))
    conn.commit()
    
    print query_domain.domain,query_domain.reg_name,query_domain.reg_email,query_domain.reg_phone


def main():

    domain_list = []
    domain_list = get_domain()

    total_domain_count = len(domain_list)
    count = 0
    print total_domain_count
    while count * THREADNUM < total_domain_count:
        domains = domain_list[count * THREADNUM: (count + 1) * THREADNUM]
        gevent.joinall(
            [gevent.spawn(check_domain, str(domain.strip())) for domain in domains])
        count = count + 1


if __name__ == '__main__':
    main()
    
    conn.close()
