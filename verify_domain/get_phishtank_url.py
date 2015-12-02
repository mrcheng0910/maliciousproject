#!/usr/bin/python
#encoding:utf-8

import MySQLdb

conn = MySQLdb.Connection(host='172.26.253.3',user='root',passwd='platform',db='cyn_malicious_domain',charset='utf8')
cursor = conn.cursor()

def main():

    
    sql = 'SELECT url,hash FROM url_detail_info WHERE virustotal_detail is NULL or virustotal_detail =" " '
    cursor.execute(sql)
    result_list = cursor.fetchall()

    for url in result_list:
        # print url
        cursor.execute('INSERT INTO virustotal_info (url,hash,source) VALUES(%s,%s,%s) ',(url[0],url[1],'1'))

    conn.commit()

    cursor.execute('UPDATE url_detail_info SET virustotal_detail = "1" WHERE virustotal_detail is NULL or virustotal_detail =" "')

    conn.commit()
    conn.close()

if __name__ == '__main__':

    main()