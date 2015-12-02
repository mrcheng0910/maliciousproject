#!/usr/bin/python
#encoding:utf-8
'''
@该文件用于完成与数据库的连接等操作
@作者：程亚楠
@时间：2014.09.16
'''

import MySQLdb

class MysqlConnection:
    
    def __init__(self):
        '''初始化连接数据库'''
        try:
            self.conn=MySQLdb.Connection(host='172.26.253.3',user='root',passwd='platform',db='cyn_malicious_domain',charset='utf8')
        except:
            print "Connect database failure"
            exit(0)
        else:
            print "Connect database success"

    def return_conn(self):
        '''返回conn连接'''
        return self.conn