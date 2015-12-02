#!C:\Python27/python
#encoding:utf-8
'''
使用socket来解析域名，得到其对应ip，可以作为验证
'''
import sys
sys.path.append('..')
from mysql_connection import MysqlConnection #数据库
import socket

def domain2ip_batch():
    """批量解析"""
    
    sql = 'select domain from url_detail_info limit 20'
    mysql = MysqlConnection()
    conn = mysql.return_conn()
    cursor = conn.cursor()
    cursor.execute(sql)
    ips = cursor.fetchall()
    
    for ip in ips:
        try:
            result = socket.getaddrinfo(ip[0], 'http')
            print ip[0],result
        except socket.error, err_msg:
            print err_msg #回显异常信息
            continue
    print 'Done'
    cursor.close()
    conn.close()

def domain2ip(domain = 'www.baidu.com'):
    """单个解析"""

    try:
        result = socket.getaddrinfo(domain, 'http')
        print domain,result
    except socket.error, err_msg:
        print err_msg #回显异常信息


#测试主函数
if __name__ == '__main__':
    
    domain = 'cieloo.info' #若测试单个域名，修改domain即可
    
    domain2ip(domain)
    #domain2ip_batch()