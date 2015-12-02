#!/usr/bin/python
#encoding:utf-8
'''
@python 实现使用Google Safe Browsing API查询url是否为恶意网址,使用的版本为3.1
@Author:程亚楠
@输入：mysql数据库中的待检测urls
@输出：将google查询结果，返回到数据库
@Date：2014.9.27
@改进方向：是否可以多线程进行，将把数据插入到数据库与google查询分开两个线程编写
'''
import datetime
import urllib2
import re
import sys
# sys.path.append('..')
# from mysql_connection import MysqlConnection    #连接数据库

#增加以下操作，是为了解决数据库中有乱码的问题
import sys
reload(sys)
sys.setdefaultencoding( "utf-8" )

class SafeBrowsingLookupClient(object):
    '''
    创建查询SafeBrowsingLookupClient类
    '''
    def __init__(self, key=''):
        '''
        完成初始化工作，version可以任意，但是格式必须为*.*，api_version必须为3.1版本，key为google api key，需在网上申请
        '''
        self.key = key
        self.version = '1.0'
        self.api_version = '3.1'
        if self.key == '':
            raise ValueError("缺少Google API，请于 Google Developers Console中申请 API Key")
        self.url_google = 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=%s&key=%s&appver=%s&pver=%s' % ('python', self.key, self.version, self.api_version)
        # mysql = MysqlConnection()
        # self.conn = mysql.return_conn()

    def lookup(self):
        '''
        查询疑似url是否为恶意网址，并插入到数据库中
        '''
        
        # lookup_sql = "SELECT  url  FROM  url_detail_info WHERE  virustotal_detail IS NULL or virustotal_detail =' ' limit 100"
        # urls=[]
        # rowcount = 0        #行数
        # cursor = self.conn.cursor()
        # try:
        #     cursor.execute(lookup_sql)
        #     urlstest = cursor.fetchall()
        #     rowcount = cursor.rowcount  #得到行数
        # except:
        #     print "无法获取数据库urls数据"
        #     sys.exit(0)
        
        # for urllist in urlstest:         #提取出urls
        #     urls.append(urllist[0])

        fr = open(sys.argv[1],'r')
        urls = fr.readlines()
        rowcount = len(urls)
        
        results = {}
        count = 0
        while count * 500 < rowcount:  #google每次最多查询500个
            inputs = urls[count * 500 : (count + 1) * 500]
            body = len(inputs)
            
            '''创建request body'''
            for url in inputs:
                body = str(body) + "\n" + self.__canonical(str(url).strip())

            response = ''
            
            '''发送http request'''
            try:
                response = urllib2.urlopen(self.url_google, body,timeout=5)
            except urllib2.URLError as e:
                if hasattr(e, 'reason'):
            #HTTPError and URLError all have reason attribute.
                    print 'We failed to reach a server.'
                    print 'Reason: ', e.reason
                elif hasattr(e, 'code'):
                #Only HTTPError has code attribute.
                    print 'The server couldn\'t fulfill the request.'
                    print 'Error code: ', e.code
            else:
                code = response.getcode()
                if code == 200:
                    results.update( self.__parse(response.read().strip(), inputs) )
                elif code == 204:
                    results.update( self.__ok(inputs) )
                elif code==400:
                    results.update( self.__errors(inputs) )
                elif code == 401:
                    results.update( self.__errors(inputs) )
                elif code == 503:
                    results.update( self.__errors(inputs) )
                else:
                    results.update( self.__errors(inputs) )                
                self.googletomysql(results)
            count = count + 1
        return rowcount

    def __canonical(self, url=''):
        '''格式化url，添加头'http://'''
        url = url.strip()
        # Remove any embedded tabs and CR/LF characters which aren't escaped.
        url = url.replace('\t', '').replace('\r', '').replace('\n', '')
        scheme = re.compile("https?\:\/\/", re.IGNORECASE)
        if scheme.match(url) is None:
            url = "http://" + url
        return url

    def __parse(self, response, urls):
        lines = response.splitlines()
        
        if (len(urls) != len(lines)):         
            return self.__errors(urls);
        results = { }
        for i in range(0, len(lines)):
            results.update({urls[i] : lines[i]})

        return results

    def __errors(self, urls):
        results = {}
        for url in urls:
            results.update({url: 'error'})
        return results

    def __ok(self, urls):
        results = {}
        for url in urls:
            results.update({url: 'ok'})
        return results
    
    def googletomysql(self,results):
        # sql = 'update url_detail_info set virustotal_detail = %s where url = %s'
        # cursor = self.conn.cursor()
        # for result in results:
        #     print  '%s   %s' % (result, results[result])
        #     cursor.execute(sql,(results[result],result))
        # self.conn.commit()
        for r in results:
            print r
        
if __name__ == "__main__":
    starttime = datetime.datetime.now()
    s = SafeBrowsingLookupClient("AIzaSyBDVJVS-dI3jQZgzPo0J1GyMr8X8qrTO3o")
    print s.lookup()
    endtime = datetime.datetime.now()
    print '程序运行时间：' + str((endtime - starttime).seconds)
    