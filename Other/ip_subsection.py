#!/usr/bin/python2.7
#encoding:utf-8
'''
@attention: 该程序将文件中的ip段导入mysql数据库中，字段为start_ip、end_ip以及城市code,状态位state，默认500个ip为一段
@author:程亚楠
@date:2014.10.4
@bug: 状态位需要设置
'''
from mysql_connection import MysqlConnection     #连接数据库
from ip_location_taobaoapi import ip2long,long2ip  #ip与长整型相互转换 

class File2Sql:
    
    def __init__(self,file_source = 'ip_block_source/anhui.txt'):
        '''初始化函数'''
        
        self.conn = MysqlConnection().return_conn()  #连接数据库
        self.file_source = file_source                                     #ip段txt文件路径和文件名
        
    def file2sql(self,num = 500):
        '''文件ip段导入到数据库中'''
                             
        sql = 'INSERT INTO ip_block (start_ip,end_ip,region_id,state) VALUES (%s,%s,"1","0")'
        cursor = self.conn.cursor()
        ip_block = file(self.file_source,mode = 'r')           #打开文件
        ip_block_lines = ip_block.readlines()                     #得到所有ip段
        linecount = len(ip_block_lines)                                #得到行数
        for line in range(linecount):
            list_ip = ip_block_lines[line].strip().split('\t')      #分隔为列表
            long_start_ip = ip2long(str(list_ip[0]))
            long_end_ip = ip2long(str(list_ip[1]))
            row_count = long_end_ip - long_start_ip+1
            counts = row_count/num
            for count in range(counts):
                change_ip = long_start_ip + num
                if change_ip<long_end_ip:
                    print long2ip(long_start_ip),long2ip(change_ip)
                    cursor.execute(sql,(long2ip(long_start_ip),long2ip(change_ip)))
                    long_start_ip = change_ip+1
                else:
                    print long2ip(long_start_ip),long2ip(long_end_ip)
                    cursor.execute(sql,(long2ip(long_start_ip),long2ip(change_ip)))
                    break
            self.conn.commit()
                                  
        ip_block.close()
        cursor.close()
        self.conn.close()
        
if  __name__ == '__main__':
    file_to_sql = File2Sql()
    file_to_sql.file2sql()