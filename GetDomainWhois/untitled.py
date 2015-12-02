import sys
import time
from PyQt4 import QtGui, QtCore, QtWebKit
from BeautifulSoup import BeautifulSoup


class Sp():
    def save(self):
        print "call"
        data = self.webView.page().currentFrame().documentElement().toInnerXml()
        open("htm.txt","w").write(data)

        print 'finished'
        time.sleep(5)
        print 'finisheed......2'
	 #sys.exit()
        
    def txtfile(self):
	print "starting..."    

    def main(self):
        self.webView = QtWebKit.QWebView()	
        self.webView.load(QtCore.QUrl("http://www.cxw.com/domain/searchdomain?domainName=www.ifeng.com"))
        # self.webView.show()
        QtCore.QObject.connect(self.webView,QtCore.SIGNAL("loadFinished(bool)"),self.save)


app = QtGui.QApplication(sys.argv)
s = Sp()
#s.txtfile()
s.main()

sys.exit(app.exec_())
#sys.exit()