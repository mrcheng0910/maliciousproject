#!/usr/bin/python
#encoding:utf-8
"""
@功能：使用virustotal 开发者API将疑似url提交查询，并将结果存入数据库中
@version：0.1
@Author：程亚楠
@Date：2014.10.28
@Note：改进方向。1、加快查询速率；2、提交列表数据；3、多申请开发者api；4、异常情况的判断；5、多线程；6、将一些函数合并
"""
import json
import urllib
import urllib2
import sys
from mysql_connection import MysqlConnection

def createfield(total=0):
	"""生成数据库的匹配字段,e.g.,a,b,...,aa,ab,...,ba,bb..."""

	if total == 0:
		return ''
	num1 = total / 26
	num2 = total % 26
	field =''
	if num1 == 0:
		for i in xrange(97,97+num2):
			field += ',' + chr(i)
		return field
	elif num1 == 1:
		for i in xrange(97,97+26):
			field += ',' + chr(i)
		for i in xrange(97,97+num2):
			field += ',a' + chr(i)
		return field
	else:
		for i in xrange(97,97+26):
			field += ',' + chr(i)
		for i in xrange(97,97+26):
			field += ',a' + chr(i)
		for i in xrange(97,97+num2):
			field += ',b' + chr(i)
		return field


class VirusTotalUrls:
	"""
	VirusTotalUrls类来检测输入的url是否为恶意域名
	"""

	def __init__(self,url='',apikey='675191178cb1ebdb20a8a01674d953367a21162ec3e83d468aca7c405ad3a70d'):
		"""初始化,apikey是virustotal申请的public api，https://www.virustotal.com"""
		self.apikey = apikey
		self.url = url
		self.resource = url
		self.scan_id = ''
			
	def send_urls_scan(self):
		"""发送URL给virustotal进行扫描，返回scan_id"""

		if len(self.url)==0:                                         #url is empty
			print 'url can\'t be empty'
			#sys.exit(1)
			return False

		url_scan = "https://www.virustotal.com/vtapi/v2/url/scan"    #调用api网址
		parameters = {"url": self.url,"apikey": self.apikey}
		body_data = urllib.urlencode(parameters)                      #编码
		req = urllib2.Request(url_scan, body_data)
		try:
			response = urllib2.urlopen(req)
		except urllib2.URLError as e:
			if hasattr(e, 'reason'):
				print 'We failed to reach a server.'
				print 'Reason: ', e.reason
				#sys.exit(1)
				return False
			elif hasattr(e,'code'):
				print 'The server couldn\'t fulfill the request.'
				print 'Error code:',e.code
				return False
				#sys.exit(1)

		if response.code == 204:
			print 'Request rate limits 4 requests/minute'    #virustotao限制public api每分钟查询次数不超过4次
			sys.exit(0)
		elif response.code == 200:
			content = response.read()
			print content
			#response_code = ''
			response_code = json.loads(content)['response_code']
			
			if response_code == 0:             #不同的response_code，代表情况不同
				print self.url + ' ,This site is not present virustotal\'s  database'
			elif response_code == -2:
				print self.url + ' ,the requested item is still queued for analysis'
			elif response_code == 1:

				verbose_msg = ''
				scan_id = ''
				scan_date = '' 
				#url = ''
				#permalink = ''
				#resource = ''

				verbose_msg = json.loads(content)['verbose_msg']
				scan_id = json.loads(content)['scan_id']
				scan_date = json.loads(content)['scan_date']
				#url = json.loads(content)['url']
				#permalink = json.loads(content)['permalink']
				#resource = json.loads(content)['resource']

				#print response_code
				#print verbose_msg + '(扫描请求已经成功提交，稍后可以查询报告结果)'
				print verbose_msg
				print scan_id
				print scan_date
				#print url
				#print permalink
				#print resource
				return scan_id

	def retrieving_url_report(self,scan_id=''):
		"""检索查询的url检测报告，若存在返回检测报告content，否则返回False"""

		url_retrieving = "https://www.virustotal.com/vtapi/v2/url/report"
		parameters = {"resource": self.resource,"apikey": self.apikey}
		body_data = urllib.urlencode(parameters)
		req = urllib2.Request(url_retrieving, body_data)

		try:
			response = urllib2.urlopen(req)
		except urllib2.URLError as e:
			if hasattr(e, 'reason'):
				print 'We failed to reach a server.'
				print 'Reason: ', e.reason
				#sys.exit(1)
				return False
			elif hasattr(e,'code'):
				print 'The server couldn\'t fulfill the request.'
				print 'Error code:',e.code
				#sys.exit(1)
				return False

		if response.code == 204:
			print 'Request rate limits 4 requests/minute'     #virustotao限制public api每分钟查询次数不超过4次
			sys.exit(0)
		elif response.code == 200:
			content = response.read()
			return content

			
	def analysis_report(self,url_id,content):
		"""解析检测报告，并将结果返回，否则返回False"""
				
		conn = MysqlConnection().return_conn()
		cursor = conn.cursor()

		response_code = json.loads(content)['response_code']
		if response_code == 0:                 #不同的response_code，代表情况不同
			print self.url + ' ,This site is not present virustotal\'s  database'
		elif response_code == -2:
			print self.url + ' ,the requested item is still queued for analysis'
		elif response_code == 1:
			url = json.loads(content)['url']               #查询的url
			scan_date = json.loads(content)['scan_date']   #扫描时间
			positives = json.loads(content)['positives']   #是恶意网址的扫描引擎数量
			total = json.loads(content)['total']           #总共使用扫描引擎数量
			scans = json.loads(content)['scans']

			result_list=[]
			i = 0
			for key in scans.keys():
				if  scans[key]['detected'] == True:
					result_list.append({str(key):str(scans[key]['result'])})
					i = i + 1

			sql = 'INSERT INTO virustotal_details(id,url,subtime,total,positives' + createfield(i) + ')'
			num = ' "%s"' * i
			li  = num.split(' ')
			sql = sql + ' VALUES ("%s","%s","%s","%s","%s" ' + ','.join(li) + ')'


			value = (str(url_id),str(url),str(scan_date),str(total),str(positives))+tuple(result_list)
			sql = sql % value
			print sql
			
			cursor.execute(sql)
			conn.commit()
			cursor.close()
			conn.close()
	


def main():

    #获取需要检测urls列表
	sql = 'select id,url from url_detail_info where virustotal_detail is NULL or virustotal_detail = "" limit 1'
	conn = MysqlConnection().return_conn()
	cursor = conn.cursor()
	cursor.execute(sql)
	urls = cursor.fetchall()
	cursor.close()
	conn.close()
    
	if len(urls) == 0:
		print 'There is not url needs to be scaned with virustotal'
		sys.exit(0)

	for url in urls:
        
		url_scan = VirusTotalUrls(url[1])
		content = url_scan.retrieving_url_report()
		if not content:
			print url[1] + " , Please check this url later"
			continue
		url_scan.analysis_report(url[0],content)

if __name__ == '__main__':
	main()