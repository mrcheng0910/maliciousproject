#!C:\Python27\python
#encoding:utf-8
import urllib2
import json
import MySQLdb
import socket
import sys
sys.path.append('..')
from mysql_connection import MysqlConnection
reload(sys)
sys.setdefaultencoding('utf8')

UPDATE_RATE = 50

mysql = MysqlConnection()
conn = mysql.return_conn()
cursor = conn.cursor()

cursor.execute("SELECT  domain_info FROM url_detail_info where domain_type = '1' and country = '' or country is null" ) #获得要查询的ip
ips = cursor.fetchall()

sql = "update url_detail_info set country = %s,region = %s,city = %s,isp = %s  where domain_info = %s "
i = 0
for ip in ips:
    if ip[0] == '0':
        continue
    apiurl = "http://ip.taobao.com/service/getIpInfo.php?ip=%s" % ip[0]

    try:
        # headers = {'User-Agent':'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6'}

        # req = urllib2.Request(url = apiurl,headers = headers)
        # req1 = urllib2.urlopen(req)
        # content = req1.read()
        content = urllib2.urlopen(apiurl,timeout = 15).read()
        # req1.close()
    
    except urllib2.HTTPError,e:    #HTTPError必须排在URLError的前面
        print "The server couldn't fulfill the request"
        print "Error code:",e.code
        print "Return content:",e.read()
        continue

    except urllib2.URLError,e:    #无法得到service
        print "Failed to reach the server"
        print "The reason:",e.reason
        continue
    except socket.timeout as e:
        print 'timeout'
        continue

    else:

        data = json.loads(content)['data']  
        code = json.loads(content)['code']  
        if code ==0:
            str_print = "IP: %s  From: %s%s%s  ISP: %s" % (data['ip'], data['country'], data['region'], data['city'], data['isp'])
            print str_print.encode("GBK") #在windows下正确输出
            try:
                cursor.execute(sql,(data['country'],data['region'],data['city'],data['isp'],ip[0]))
                i = i + 1
                if i == UPDATE_RATE:
                    conn.commit()
                    i = 0
            except:
                print 'Update failed'
                conn.rollback()
                continue      #继续执行

        else:
            print data
         
conn.commit()
cursor.close()
conn.close()
print 'done'