#encoding:utf-8
"""
功能：多线程检测url是否在线，http_code：200,表示在线，http_code:404,等表示不在线
作者：程亚楠
时间：2014.10.31
注意：多线程不能打开太多，否则会出现丢包现象，这也是程序需要改进的地方，
尝试将线程数据返回到主函数，主函数来把数据存入到数据库中
输入/输出：使用url_details_info中的url字段作为输入，online字段作为输出
"""
import pycurl
import StringIO
import threading
from mysql_connection import MysqlConnection
import time

#防止特殊字符造成的乱码
import sys
reload(sys)
sys.setdefaultencoding( "utf-8" )


URL_COUNT = 0    #检测的url个数
THREAD_NUM = 10   #线程数量
RESULTS_NUM = 100  #每隔results_num个结果后，存入数据库
result_urls = []   #结果列表
lock = threading.Lock() #线程锁

def online(checkurl='',rowcount = 0):
    """检测url是否在线主函数
    """

    global URL_COUNT
    global result_urls

    #构造pycurl对象，用来检测
    c = pycurl.Curl()
    b = StringIO.StringIO()
    c.setopt(pycurl.URL, str(checkurl))
    c.setopt(pycurl.USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)") #伪造浏览器头部
    c.setopt(pycurl.WRITEFUNCTION,b.write)
    c.setopt(pycurl.FOLLOWLOCATION, 1)
    c.setopt(pycurl.SSL_VERIFYPEER, 0)  #用来访问https
    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    c.setopt(pycurl.MAXREDIRS, 5)
    c.setopt(pycurl.TIMEOUT,10)   #timeout

    try:
        c.perform()      #执行
    except pycurl.error,error:
        errorno,errorstr = error
        print errorno,errorstr
    http_code = c.getinfo(c.HTTP_CODE)    #得到返回码
    dir_url = c.getinfo(c.EFFECTIVE_URL)  #得到重定向网址
    print checkurl + ' ' + str(http_code) +' ' + dir_url
    
    c.close()
    b.close()

    lock.acquire()  #线程锁

    result_urls.append({'url': checkurl,'http_code': http_code,'dir_url': dir_url})
    URL_COUNT += 1

    if URL_COUNT % RESULTS_NUM == 0 or URL_COUNT == rowcount:   #每隔RESULTS_NUM个url时候，将结果存入到数据库中
        print result_urls

        sql = 'UPDATE url_detail_info SET online = %s WHERE url = %s '
        conn = MysqlConnection().return_conn()
        cursor = conn.cursor()
        for url in result_urls:
            cursor.execute(sql,(url['http_code'],url['url']))

        conn.commit()   #更新
        cursor.close()  #关闭
        conn.close()
    
        del result_urls[:]      #清除已存入的url探测结果
        if URL_COUNT == rowcount:
            print 'end'
          
    lock.release() #解锁


def main():

    sql = 'SELECT url from url_detail_info limit 1000'
    conn = MysqlConnection().return_conn()
    cursor = conn.cursor()
    cursor.execute(sql)
    url_list = cursor.fetchall()
    rowcount = cursor.rowcount   #需要检测的url数量

    count = 0

    while count*THREAD_NUM < rowcount:
        input_urls = url_list[count * THREAD_NUM:(count+1) * THREAD_NUM]
        for url in input_urls:
            t = threading.Thread(target = online,args = (url[0],rowcount,))
            t.start()
        count += 1
        time.sleep(2)  #防止线程过多，造成丢包

    cursor.close()
    conn.close()

#运行测试
if __name__ == '__main__':
    main()