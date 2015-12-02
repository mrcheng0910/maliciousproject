#encoding:utf-8
'''
@function: 从phishtank网站下载钓鱼网站的json文件，并且存储到数据库中
@date: 2014.11.29
@update_date:2014.12.4,增加了异常处理情况
'''

import json
import sys
import MySQLdb
sys.path.append('..')
from mysql_connection import MysqlConnection
from urlparse import urlparse
reload(sys)
sys.setdefaultencoding( "utf-8" )

class PhishsiteData:
    '''
    phishwebsite类
    '''
    def  __init__(self):
        ''' 初始化，连接数据库'''
        
        self.mysql = MysqlConnection()
        self.conn = self.mysql.return_conn()
        
    def json2mysql(self):
        '''
        把json导入mysql数据库data表中
        '''
        
        filedata = open('data.json')
        jsdata = json.load(filedata)
        cursor = self.conn.cursor()

        cursor.execute('SELECT hash from url_detail_info')
        hash_list = cursor.fetchall()


        sql = "INSERT INTO  url_detail_info (url,domain,domain_type,domain_info,type,target,submission_time,verification_time,online,verified,url_source,hash,virustotal_detail) VALUES( %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        update_num = 0      #统计本次更新url数量
        
        print 'Updating....'


        try:

            for item in jsdata:   #添加最新的url
    

                url_hash = hash(item['url'])
                if not (str(url_hash),) in hash_list: #使用hash值来去重

                    print 'Add url : ' + item.get('url','0')

                    url = item.get('url','0')  #得到url
                    domain = urlparse(item.get('url','0')).netloc #得到domain
                    if not item.get('details'): 
                        ip_address = '0'
                    else:
                        ip_address = item.get('details','0')[0].get('ip_address','0') #得到ip
                    target = item.get('target','0')                      #得到target
                    submission_time = item.get('submission_time','0')    #得到submission_time
                    verification_time = item.get('verification_time','0')#得到verification_time
                    online = item.get('online','0')                      #得到online
                    verified = item.get('verified','0')                  #得到verified
                    phish_id = item.get('phish_id','0')                  #得到phish_id

                    update_num = update_num + cursor.execute(sql,(url,domain,'1',ip_address,'phishing',target,submission_time,verification_time,online,verified,phish_id,url_hash,'1'))
                    cursor.execute('INSERT INTO virustotal_info (url,hash,source) VALUES(%s,%s,%s) ',(url,url_hash,'1'))
                    
                    if update_num % 800 == 0: #每800个result插入到数据库中
                        self.conn.commit()

            self.conn.commit()       #更新

            print 'Success update '+str(update_num)+' url(s)'

            filedata.close()
            cursor.close()
            self.conn.close()

        except MySQLdb.Error,e:  #异常处理
            print "Mysql Error %d: %s" % (e.args[0], e.args[1])

    
if __name__ == '__main__':
    data = PhishsiteData()
    data.json2mysql()