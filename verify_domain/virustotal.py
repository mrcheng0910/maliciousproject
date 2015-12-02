#!/usr/bin/python
# encoding:utf-8
"""
调用VirusTotal私有APIkey，进行查询恶意域名查询，并且返回结果。
@author:侯鑫美、程亚楠
@date:2015.3.31
@version1.0
"""
import urllib2
import requests
import socket

socket.setdefaulttimeout(5)

class VirustotalVerifyUrl:
    """
    """

    def __init__(self, url=' ', apikey='e3c12bf4eea6b61e25a45601d0d848dc36a8ede5499688129920c6e4240ad20d'):
        """
        初始化，apikey，待查询url
        """
        self.apikey = apikey
        self.verify_url = url

    def report_url(self):
        """
        Use VirusTotal API to verify urls, and return verify_result(<dic>)
        """

        if not self.verify_url:
            print 'Verify url is None!'
            return 

        url = "https://www.virustotal.com/vtapi/v2/url/report"
        parameters = {
            "resource": self.verify_url, "apikey": self.apikey, "scan": 1, "allinfo": 1} #接口参数

        try:
            response = requests.post(url, parameters)
            verify_result = response.json()
            return verify_result
        except urllib2.HTTPError, error:
            print 'HTTPError--code:' + str(error.code)
            return 
        except urllib2.URLError, error:
            print 'URLError--reason:' + str(error.reason)
            return 
        except Exception, e:
            print e
            return


#demo
def main():

    verify_result = {}
    verify_url = 'http://news.hitwh.edu.cn/news_show.asp?id=18769'
    virustotal = VirustotalVerifyUrl(verify_url)
    verify_result = virustotal.report_url()
    if not verify_result:
        return

    for i in verify_result:
        print i , verify_result[i]


if __name__ == '__main__':
    main()