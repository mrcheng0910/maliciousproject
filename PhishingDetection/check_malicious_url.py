#!/usr/bin/python
#encoding:utf-8

import sys
from mysql_connection import MysqlConnection
reload(sys)
sys.setdefaultencoding( "utf-8" )

if len(sys.argv) <3:
    print "wrong format,eg. python check_malicious_url.py  input.txt  output.txt"
    sys.exit(0)

fr_check_url = open(sys.argv[1],'r')
fw_result_url = open(sys.argv[2],'w')

mysql = MysqlConnection()
conn = mysql.return_conn()
cursor = conn.cursor() 
check_url_list = fr_check_url.readlines()
for url in check_url_list:

    sql = 'SELECT * FROM url_detail_info WHERE url LIKE ' +'\"' + str(url.strip())+'%'+'\"' 
    cursor.execute(sql)
    result = cursor.fetchall()
    if not result:
        fw_result_url.write(url.strip() + '\t' + 'No' +'\n')
    else:
        fw_result_url.write(url.strip() + '\t' + 'Yes' +'\n')

print 'Check end'
fr_check_url.close()
fw_result_url.close()