#!/usr/bin/python
# encoding:utf-8
"""

"""
import urllib2
import requests


class VirustotalVerifyUrl:
    """
    """

    def __init__(self, url=' ', apikey='e3c12bf4eea6b61e25a45601d0d848dc36a8ede5499688129920c6e4240ad20d'):

        self.apikey = apikey
        self.verify_url = url

    def report_url(self):
        """
        Use VirusTotal API to verify urls, and return verify_result(<dic>)
        """

        if not self.verify_url:
            print 'Verify url is None!'
            return None

        url = "https://www.virustotal.com/vtapi/v2/url/report"
        parameters = {
            "resource": self.verify_url, "apikey": self.apikey, "scan": 1, "allinfo": 1}

        try:
            response = requests.post(url, parameters)
            verify_result = response.json()
            return verify_result
        except urllib2.HTTPError, error:
            print 'HTTPError--code:' + str(error.code)
            return None
        except urllib2.URLError, error:
            print 'URLError--reason:' + str(error.reason)
            return None
        except Exception, e:
            print e
            return None


def main():

    verify_result = {}
    verify_url = 'http://news.hitwh.edu.cn/news_show.asp?id=18769'
    virustotal = VirustotalVerifyUrl(verify_url)
    verify_result = virustotal.report_url()

    for i in verify_result:
        print i , verify_result[i]
    # print verify_result


if __name__ == '__main__':
    main()
