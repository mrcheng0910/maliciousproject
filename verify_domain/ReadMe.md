## <center>恶意域名验证</center>
通过VirusTotal提供开发着API接口，对恶意域名进行二次验证。

### 文件介绍

- virustotal.py，为VirusTotal访问接口程序,通过调用对象调用，返回验证结果。如下：

    	from virustotal import VirustotalVerifyUrl
    	virustotal = VirustotalVerifyUrl(self.url)
    	self.details = virustotal.report_url()

- sql_command.py，为数据接口程序，对数据库进行统一查询更新操作。
- verify_url.py，该程序为查询程序，对恶意域名进行查询并进行更新到数据库。
- check\_malicious\_url.py,该程序为本地验证接口。

### 运行环境
- 操作系统：Ubuntu14.04，Pyhton2.7.6
- 安装Python包：gevent

### 其他
他人若需要验证恶意域名，只需要使用virustotal.py文件，该文件可执行验证。
