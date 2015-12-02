#!/usr/bin/python
#encoding:utf-8
"""
验证数据库中的恶意域名，使用gevent进行多线程操作
@author:程亚楠
@date:2015.3.31
@version1.0
"""
import sys
import gevent
from gevent import monkey;
monkey.patch_all()
from sql_command import MysqlConnection
from virustotal import VirustotalVerifyUrl

THREAD_NUM = 3  #线程数

class VerifyUrl:

    def __init__(self,url=''):

        """
        初始化操作
        """

        self.url = url
        self.verify_result = []
        self.response_code = ''
        self.date = ''
        self.total = ''
        self.positives = ''
        self.ip = ''
        self.resolution_country = ''
        self.details = {}
        self.category = []

        self.verify_domain()
        self.update_db()


    def verify_domain(self):
        """
        执行查询验证
        """

        if not self.url:
            return

        scans = {}

        virustotal = VirustotalVerifyUrl(self.url)
        self.details = virustotal.report_url()
        response_code = self.details.get('response_code')
        print response_code
        if response_code != 1:
            return

        scans = self.details.get('scans',False)
        if scans:
            for name in scans:
                if scans[name].get('detected'):
                    # print name,scans[name]
                    self.verify_result.append({name:scans[name]['result']})

        self.date = self.details.get('last_seen','')
        self.total = self.details.get('total')
        self.positives = self.details.get('positives')
        self.ip = self.details.get('additional_info','').get('resolution','')
        self.resolution_country = self.details.get('additional_info').get('resolution_country','')
        self.category = self.details.get('additional_info').get('categories','')
        # print self.date,self.total,self.positives,self.ip,self.resolution_country,self.category
        print self.url


    def update_db(self):
        """
        更新查询结果到数据库中
        """
        sql = 'UPDATE virustotal_info set date="%s",total = "%s",positives="%s",ip="%s",resolution_country="%s",category="%s",verify_result="%s" WHERE url = "%s"' \
                % (self.date,self.total,self.positives,self.ip,self.resolution_country,self.category,str(self.verify_result),self.url)
        sql_query = MysqlConnection(host='172.26.253.3',user='root',passwd='platform',db='cyn_malicious_domain')
        sql_query.execute_update(sql)


def get_url():
    """
    获取要查询的恶意域名url
    """

    sql = 'SELECT url FROM virustotal_info WHERE total is NULL or total =" " '
    result_list = []
    sql_query = MysqlConnection(host='172.26.253.3', user='root', passwd='platform', db='cyn_malicious_domain')

    result_list = sql_query.execute_query(sql)

    if result_list:
        return result_list
    else:
        return

if __name__ == '__main__':
    """
    执行查询验证
    """

    url_list = get_url()
    if not url_list:
        sys.exit(0)
    # for url in url_list:
    #     urlobj = VerifyUrl(url[0])
    #     urlobj.verify_domain()
    #     urlobj.update_db()

    rowcount = len(url_list)
    count = 0
    while count * THREAD_NUM < rowcount:
        urls = url_list[count * THREAD_NUM: (count + 1) * THREAD_NUM]
        gevent.joinall([gevent.spawn(VerifyUrl, url[0]) for url in urls])
        # gevent.joinall([
        #     gevent.spawn(check_ip,ips[0][0] ),
        #     gevent.spawn(check_ip,ips[1][0] ),
        #     gevent.spawn(check_ip,ips[3][0] ),
        #     gevent.spawn(check_ip,ips[2][0] ),
        #     gevent.spawn(check_ip,ips[4][0] ),
        #     ])
        urls = []
        count = count + 1
