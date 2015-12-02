#!/usr/bin/env python  
# -*- coding: utf-8 -*- 
import urllib2
import urllib
import requests
import json

    
def reportURL(urls,apikey):
    
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    parameters = {"resource": urls, "apikey": apikey,"scan":1,"allinfo":1}

    try:
        response = requests.post(url, parameters)
        json = response.json()
        return json
    except urllib2.HTTPError, error:
        print 'HTTPError--code:'+str(error.code)
        return None
    except urllib2.URLError,error:
        print 'URLError--reason:'+str(error.reason)
        return None
    except Exception,e:
        print e
        return None

def main():

    detect_result = {}
    scans = {}
    response_code = ''

    # url = 'down.tt6786.com'
    url = 'www.baidu.com'
    apikey = 'e3c12bf4eea6b61e25a45601d0d848dc36a8ede5499688129920c6e4240ad20d'
    detect_result = reportURL(url,apikey)
    print detect_result
    scans = detect_result.get('scans',False)
    if scans:
        for name in scans:
            if scans[name].get('detected'):
                print name,scans[name]
    response_code = detect_result.get('response_code')
    print response_code
    scan_date = detect_result.get('response_code')
    last_seen = detect_result.get('last_seen')
    additional_info = detect_result.get('additional_info')
    # print additional_info
    print additional_info.get('resolution_country')
    print additional_info.get('resolution')
    print additional_info.get('categories')


if __name__ == '__main__':

    main()
