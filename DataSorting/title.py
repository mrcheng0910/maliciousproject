#encoding:utf-8
import urllib
import socket
import urllib2
import sys
import time
sys.path.append('..')
from BeautifulSoup import BeautifulSoup
from mysql_connection import MysqlConnection

mysql = MysqlConnection()        #连接数据库
conn = mysql.return_conn()
cursor = conn.cursor()

socket.setdefaulttimeout(3)

cursor.execute('SELECT url from test limit 30')
url_list = cursor.fetchall()
sql = 'update test set title = %s where url = %s'

for url in url_list:
    try:
    	print url[0]
        content = urllib.urlopen(url[0]).read()
        
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
    except IOError,e:
        if e.message=="time out":
            print 'test'
            #time.sleep(50)
            continue

    else:
        soup = BeautifulSoup(content)
        flag = soup.find('title')
        if flag is None:
            print 'is none'
            continue
        else:
            title = soup.find('title').text.encode('GBK')
            cursor.execute(sql,(title,url[0]))
            conn.commit()
            print title

cursor.close()
conn.close()