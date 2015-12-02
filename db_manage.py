# -*- coding:utf-8 -*- 
#!/usr/bin/python
# Filename : database.py 

import MySQLdb
import iptools
import filelib

class Database(object):
    def __init__(self,database,ip="172.26.253.3",user="root",password="platform"): 
        self.database = database
        self.ip = ip
        self.user = user
        self.password = password

    def connect(self):
        try:
            self.db = MySQLdb.connect(self.ip,self.user,self.password,self.database,charset="gbk" )
        except:
            print "Could not connect to MySQL server."
            exit(0)
        try:
            self.cursor = self.db.cursor()
        except (AttributeError, MySQLdb.OperationalError):
            self.connect()
        return self.cursor
        
    def close(self):
        self.db.commit()
        self.db.close()
        
    def search_code(self,ip):
        sql="select address from ip_address where start_ip<=%s and end_ip>=%s"
        num = self.cursor.execute(sql,(ip,ip))
        if num != 0:
            code = self.cursor.fetchone()
            return code[0]
        else:
            return 0
            
    def search_address(self,code):
        sql = 'select province,city,area from area_code where code=%s'
        num = self.cursor.execute(sql,code)
        if num != 0:
            (province,city,area) = self.cursor.fetchone()
            return (province,city,area)
        else:
            return ('0','0','0')
            
    def search_vul(self,version):
        num = version.split('.')
        table = 'version_'+num[0]
        bind = num[0]
        if num[0] == '9':
            table = '`version_'+num[0]+'.'+num[1].split('-')[0]+'`'
            bind = num[0]+'.'+num[1].split('-')[0]
        sql = 'SELECT CVENo FROM (SELECT CVENo,'+table+' FROM vul_database WHERE FIND_IN_SET('+bind+',version)) AS version_new WHERE FIND_IN_SET(%s,'+table+')'
        #print sql % version
        num = self.cursor.execute(sql,version)
        if num != 0:
            vul = self.cursor.fetchall()
            return vul
        else:
            return '0'
    def search_vul_id(self,version):
        num = version.split('.')
        table = 'version_'+num[0]
        bind = num[0]
        if num[0] == '9':
            table = '`version_'+num[0]+'.'+num[1].split('-')[0]+'`'
            bind = num[0]+'.'+num[1].split('-')[0]
        sql = 'SELECT id FROM (SELECT id,'+table+' FROM vul_database WHERE FIND_IN_SET('+bind+',version)) AS version_new WHERE FIND_IN_SET(%s,'+table+')'
        #print sql % version
        num = self.cursor.execute(sql,version)
        if num != 0:
            vul = self.cursor.fetchall()
            return vul
        else:
            return '0'
            
    def search_vul_cveno(self,version_start,version_end):
        sql = 'SELECT CVENo FROM version_vul RIGHT JOIN vul_database ON version_vul.vul_code = vul_database.id WHERE version_vul.version_start = %s AND version_vul.version_end = %s '
        num = self.cursor.execute(sql,(version_start,version_end))
        if num != 0:
            cveno = self.cursor.fetchall()
            return cveno
        else:
            self.find_vul(version_start,version_end)
            sql = 'SELECT CVENo FROM version_vul RIGHT JOIN vul_database ON version_vul.vul_code = vul_database.id WHERE version_vul.version_start = %s AND version_vul.version_end = %s '
            num = self.cursor.execute(sql,(version_start,version_end))
            if num != 0:
                cveno = self.cursor.fetchall()
                return cveno
            else:
                return '0'
    
    def find(self,line,data):
        data_list = line.split('#') 
        if len(data[2]) == 0:
            if data[0] == data_list[0]:
                for i in range(1,len(data_list)):
                    data[2].append(data_list[i].strip('\n'))    
        else:
            if data[1] != data_list[0]:
                for i in range(1,len(data_list)):
                    data[2].append(data_list[i].strip('\n'))
            else:
                for i in range(1,len(data_list)):
                    data[2].append(data_list[i].strip('\n'))
                new_list = list(set(data[2]))
                for tmp in new_list:
                    if tmp == '0':
                        continue
                    sql = 'insert into version_vul (version_start,version_end,vul_code) values(%s,%s,%s)'
                    self.cursor.execute(sql,(data[0],data[1],tmp))
                data = 'end'
        return data 

    def find_vul(self,version_start,version_end):
        data = [version_start,version_end,[]]
        filelib.readFile("ver-vul",10000,lambda e,f: self.find(e,f),data)
        
    def run(self,line,data):
        version = line.strip('\r\n')
        vuls = self.search_vul_id(version)
        line = version
        for vul in vuls:
            line = line + '#' + str(vul[0])
        data.write(line+'\n')
        return data
        
    def update_version_vul(self,filename):
        sql = 'TRUNCATE TABLE version_vul'
        self.cursor.execute(sql)
        fw = open("ver-vul","w")
        filelib.readFile(filename,10000,lambda e,f: self.run(e,f),fw)
        fw.close()
        
    def search_dns_vul(self,ip):
        IP = iptools.ipv4.ip2long(ip)
        sql = 'select version_start,version_end from config_result where ip = %s'
        num = self.cursor.execute(sql,IP)
        if num != 0:
            (start,end) = self.cursor.fetchone()
            vul = self.search_vul_cveno(start,end)
            return vul
        else:
            return '0'
            
    def search_province_ip(self,province):
        sql = 'SELECT ip FROM detect_ip WHERE address div 10000 = (SELECT code DIV 10000 FROM area_code WHERE area = %s)'
        num = self.cursor.execute(sql,province.decode('utf8'))
        if num != 0:
            ip = self.cursor.fetchall()
            return ip
        else:
            return '0'