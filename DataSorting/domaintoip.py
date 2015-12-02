#!C:\Python27\python  
#encoding:utf-8  

import sys
sys.path.append('..')
import socket
import random
from mysql_connection import MysqlConnection
import select
from DNS import Lib
import datetime
from DNS import Type
from DNS import Class
from DNS import Opcode

A_FLAG = 1            #A记录标识
CNAME_FLAG = 2        #CNAME标识
NXDOMAIN_FLAG = 3     #NXDOMAIN标识
SERVFAIL_FLAG = 4     #SERVFAIL标识
ANSWER_EMPTY_FLAG = 5 #ANSWER空标识
UPDATE_RATE = 100


class DomainToIp:
    
    def __init__(self,DHOST='114.114.114.114'):
        '''
        初始化类DomainToIp，连接数据库，DNS服务器ip地址可以更改
        '''
        
        self.DHOST = DHOST                     #DNS 服务器的地址
        self.DPORT = 53                        #默认端口是53
        self.tid = random.randint(0,65535)     #tid为随机数
        self.opcode = Opcode.QUERY             #标准查询

        self.qtype = Type.A                                 #查询类型为A
        self.qclass = Class.IN                              #查询类IN
        self.rd = 1                                                   #期望递归查询
        
        self.mysql = MysqlConnection()        #连接数据库
        self.conn = self.mysql.return_conn()
        
    def send_domain_receive_ip(self):
        '''
        解析domain name对应的ip，并保存到数据库
        '''
      
        sql = 'SELECT domain from url_detail_info limit 20' #where domain_type is NULL OR domain_type = ""'
        cursor = self.conn.cursor()
        cursor.execute(sql)
        domains = cursor.fetchall()    #获取数据库中ip为空的数据
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)                               #建立一个UDP套接字（SOCK_DGRAM，代表UDP，AF_INET表示IPv4）
        except socket.error,msg:
            print "无法创建socket.Error code:" +str(msg[0])+',Error message:'+msg[1]    #error
            sys.exit(1)
        source_port = random.randint(1024, 65535)                                                                #随机port
        s.bind(('', source_port))                                                                                                         #绑定，检测所有接口
        
        
        domain_source = []      #发送的domain数量
        domain_result = []      #接收到的domain数量，这两个变量主要用来判断丢包情况
        result = []         #得到的结果
        '''循环发送需要解析的domain name''' 

        count = 0
        rowcount = len(domains)



        while count * UPDATE_RATE < rowcount:  #google每次最多查询500个
            inputs = domains[count * UPDATE_RATE : (count + 1) * UPDATE_RATE]

            for domain in inputs:
                
                domain_source.append(domain[0])
                
                m = Lib.Mpacker()
                m.addHeader(self.tid, 0, self.opcode, 0, 0, self.rd, 0, 0, 0, 1, 0, 0, 0)
                m.addQuestion(domain[0],self.qtype,self.qclass)
                request = m.getbuf()
                try:
                    s.sendto(request,(self.DHOST, self.DPORT))
                    print 'domain: ',domain[0]," send to Dns server:",self.DHOST
                except socket.error,reason:
                    print  reason
                    continue
                
            # result = []         #得到的结果
            
            '''循环接收收到的返回header'''   
            while 1:
                try:
                    r,w,e = select.select([s], [], [],3)
                    if not (r or w or e):
                        break
                    (data,addr) = s.recvfrom(65535)
                    u = Lib.Munpacker(data)
                    r = Lib.DnsResult(u,{})

                    
                    if r.header['status'] == 'NOERROR':
                        #print 'answers',len(r.answers),r.questions[0]['qname']

                        if len(r.answers) != 0:
                        
                            if r.answers[0]['typename'] == 'A':
                                result.append({'domain' : r.questions[0]['qname'],'domain_type': A_FLAG,'domain_info':r.answers[0]['data']})
                                domain_result.append(r.questions[0]['qname'])
                            elif r.answers[0]['typename'] == 'CNAME':
                                result.append({'domain' : r.questions[0]['qname'],'domain_type': CNAME_FLAG,'domain_info':[r.answers[1]['name'],r.answers[1]['data']]})
                                domain_result.append(r.questions[0]['qname'])
                            else:
                                print '没有这种类型，请修改程序'
                        else:
                            result.append({'domain' : r.questions[0]['qname'],'domain_type': ANSWER_EMPTY_FLAG,'domain_info': 'answerempty'}) 
                            domain_result.append(r.questions[0]['qname'])

                    elif r.header['status'] == 'NXDOMAIN':
                        result.append({'domain' : r.questions[0]['qname'],'domain_type': NXDOMAIN_FLAG,'domain_info':[r.authority[0]['name'],r.authority[0]['data'][0]]})
                        domain_result.append(r.questions[0]['qname'])
                    elif r.header['status'] == 'SERVFAIL':
                        result.append({'domain' : r.questions[0]['qname'],'domain_type': SERVFAIL_FLAG,'domain_info': 'servfail'})    #status ='SERVFAIL'情况的判断
                        domain_result.append(r.questions[0]['qname'])
                    else:
                        print 'No this type'
                except socket.error, reason:
                    print reason
                    continue
            count = count + 1

        cursor.close()
        s.close()           #关闭socket
        result_diffrences = list(set(domain_source).difference(set(domain_result)))

        self.result_diffrence(result_diffrences) #丢包的反应
        self.result2mysql(result)                #将查询到的结果插入到数据库中
        
    def result2mysql(self,results=[]):
        '''
        该函数将得到的A、CNAME，SOA 记录更新到数据库中
        '''
        
        sql = 'UPDATE url_detail_info set domain_type = %s,domain_info = %s where domain = %s'
        cursor = self.conn.cursor()
        if len(results) != 0:

            #client端显示要插入的结果
            for result in results:
                print result
            '''将结果插入的数据库中'''
            
           # for result in results:
            #    cursor.execute(sql,(str(result['domain_type']),str(result['domain_info']),result['domain']))
            print "Done"

            self.conn.commit()
            cursor.close()
            self.conn.close()

        else:
            print 'Nothing to update'
        
    
    def result_diffrence(self,result_diffrences=[]):
        
        print 'Diffrence list'
        if len(result_diffrences) == 0:
            print len(result_diffrences)
        else:
            for result_diffrence in result_diffrences:
                print result_diffrence
        
if __name__ == "__main__":
    
    domain = DomainToIp()
    domain.send_domain_receive_ip()