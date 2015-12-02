#!/usr/bin/python
# encoding:utf-8
"""
该程序主要用来执行数据库操作，查询以及更新，其他程序调用
@author:程亚楠
@date:2015.3.31
@version1.0
"""
import MySQLdb

class Database:

    def __init__(self, host='localhost', user='root', passwd='cynztt', db='malicious_detect'):
        """
        数据库初始化
        """
        self.host = host
        self.user = user
        self.passwd = passwd
        self.db = db
        self.charset = 'utf8'

    def __get_connect(self):
        """
        执行连接数据库操作
        """
        if not self.db:
            raise(NameError, 'There is not db information')
        try:
            self.conn = MySQLdb.Connection(
                host=self.host, user=self.user, passwd=self.passwd, db=self.db, charset=self.charset)
        except:
            raise(NameError, 'Connect failure')
        cursor = self.conn.cursor()
        if not cursor:
            raise(NameError, "Connect failure")
        else:
            return cursor

    def existed_white_domain(self):
        """
        执行查询操作并返回数据
        """
        sql = ' SELECT domain FROM domain_white_list '
        cursor = self.__get_connect()
        cursor.execute(sql)
        domain_tuple = cursor.fetchall()
        cursor = self.__get_connect()

        try:
            cursor.execute(sql)
            result_list = cursor.fetchall()
        except:
            raise(NameError, 'Query failure')

        return result_list

    def close_db(self):

        self.conn.commit()
        self.conn.close()

    def insert_domain_white_list(self,domain_list = []):

        cursor = self.__get_connect()
        sql = 'INSERT INTO domain_white_list (domain) VALUES(%s)'
        
        try:
            cursor.executemany(sql, tuple(domain_list))
        except:
            raise(NameError, 'update failure')
