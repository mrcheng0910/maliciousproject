#!C:\Python27/python
#encoding:utf-8
'''
@function: 从phishtank网站下载钓鱼网站的json文件
@date: 2014.8.26
@question: 开发者的key具体的使用方法需要清楚
@develop_mentenvironment: windows8.1
'''
import urllib
import datetime
import sys
sys.path.append('..')
from mysql_connection import MysqlConnection

class PhishsiteData:
    '''
    PhishsiteData类
    '''
    def __init__(self):
        '''
        初始化,key需要在phishtank网站申请，以及数据网址
        '''
        mysql = MysqlConnection()
        self.conn = mysql.return_conn()
        key =  self.phishtank_key_selection() #得到有效phitank开发者api
            
        if str(key) == "False": #没有可用key
            exit(0)
    
        self.key = key
        self.phishsite = "http://data.phishtank.com/data/"
        self.fileformat = '/online-valid.json'
        self.total = 0.0  #数据大小
    
    def phishtank_key_selection(self):
        '''
        选择可用key
        '''
        sql_lookup = "SELECT api ,used_time,update_time FROM phishtank_api "    #用来遍历所有api，包括可用和不可用
        sql_update = 'UPDATE phishtank_api SET update_time = %s'                #修改最近查询phishtank数据库时间
        sql_used = 'UPDATE phishtank_api SET used_time = %s where api = %s'     #修改当前可用api最近使用时间
        cursor = self.conn.cursor()
        cursor.execute(sql_lookup)
        apis = cursor.fetchall()
        current_time = self.get_current_time()
                         
        for api in apis:       # 寻找匹配的keys
            if api[2] == 0:    #若上次查询时间为空时操作
                cursor.execute(sql_update,current_time)
                cursor.execute(sql_used,(current_time,api[0]))
                self.conn.commit()
                cursor.close()
                self.conn.close()
                return api[0]  #返回可用api
            elif not  int(current_time[:-2]) - int(str(api[2])[:-2]):  #用来判断phishtank数据库是否更新，该数据库是每个整点开始更新，每天更新24次
                print 'phishtank远程数据暂未更新，请于 %d 分钟后再更新'  % (61 - int(current_time[-2:]))
                return False
            '''寻找有效的api'''
            if  int(current_time) - int(api[1])  >= 300:
                cursor.execute(sql_update,current_time)
                cursor.execute(sql_used,(current_time,api[0]))
                self.conn.commit()
                cursor.close()
                self.conn.close()
                return api[0]
        else:
            print '没有可用的api，请稍后查询'
            return False
    
    def get_current_time(self):
        '''该函数用来返回当前系统时间，格式为%y%m%d%h%m，使用该格式主要是为了方便计算统计'''
        current_time = datetime.datetime.now()
        return  current_time.strftime('%y%m%d%H%M')
        
    def schedule(self,a,b,c):
        '''
        显示json数据下载进度
        a:已经下载的数据块
        b:数据块的大小
        c:远程文件大小，在当前无法使用，因为header中没有content-length
       '''
        total = a*b
        total = float(total)/1000/1000
        print "数据已经下载%0.2f MB" % total
        self.total = total
            
    def archivedata(self):
        '''
        保存json数据到本地
        '''
        url = self.phishsite+self.key+self.fileformat       #下载数据的网址
        
        (filename,header) = urllib.urlretrieve(url,'data.json',self.schedule)
        print filename #测试使用
        print header  #测试使用
        print    "数据下载结束，文件大小为:%0.2fMB"  % self.total

    
if __name__ == '__main__':
    ''' 
     main下载数据
    '''
    data = PhishsiteData()
    data.archivedata()