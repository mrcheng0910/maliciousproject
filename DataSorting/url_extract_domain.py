#!/usr/bin/python
#encoding:utf-8
'''
使用mysql内置函数substring_index来提取url的域名
author：程亚楠
date：2014.9.18
输入:url_detail_info表中的url字段
输出:url_detail_info表中的domain字段
'''

from mysql_connection import MysqlConnection #数据库

def extract_domain():
    '''
    该函数提取url中的域名，以便于后续的处理，url的格式为http://*****，
    例如http://www.ifeng.com/news/abc,提取其域名为www.ifeng.com
    '''
    sql = 'select  id ,SUBSTRING_INDEX (url,"/",3)   from url_detail_info where domain is NULL OR domain = "" ' #注意domain中null和空格的处理
    sql_update = 'UPDATE url_detail_info SET domain = %s where id = %s'                                                                         #
    mysql = MysqlConnection()
    conn = mysql.return_conn()
    cursor = conn.cursor()
    cursor.execute(sql)
    urls = cursor.fetchall()
    rowcount = cursor.rowcount  #获得需要更新的行的数量
    if rowcount>0:
        for url in urls:
            cursor.execute(sql_update,(url[1][7:],url[0]))    #url[1][7:]去掉了url前的http
            print url[0],url[1][7:]
        conn.commit()  #数据库更新
        print '提取结束，共提取%s个domain' % rowcount
    else:
        print '没有可更新域名'
    cursor.close()
    conn.close()

#测试主函数
if __name__ == '__main__':
    extract_domain()