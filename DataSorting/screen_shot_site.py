import Image
import os
import Queue
import threading
import time
import math
 
cutycapt = '/usr/bin/cutycapt'
ua = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'
waitsec = 6
shotsdir = '/tmp/siteshots'
thumbdir = '/tmp/sitethumbs'
thumbsize = (500, 300)
tasks = 3
minsize = 10000
retrytimes = 2
resultcsv = '/tmp/results.csv'
csvhandle = None
 
def getSiteList():
    return [
            ('google', 'http://www.google.com.hk'), ('sina', 'http://www.sina.com.cn'),
            ('netease', 'http://www.163.com'), ('qq', 'http://www.qq.com'),
            ('sohu', 'http://www.sohu.com'), ('baidu', 'http://www.baidu.com')
            ]
 
def fetch(name, url):
    file = shotsdir + '/' + name + '.png'
    fileopt = '"' + file + '"'
    urlopt = '"' + url + '"'
    uaopt = '"' + ua + '"'
    command = cutycapt + ' --java=on --plugins=on --user-agent=' + uaopt + ' --out=' + fileopt + ' --url=' + urlopt + ' --delay=' + str(waitsec * 1000) + ' --max-wait=' + str(waitsec * 3 * 1000)
    #print(command) 
    os.popen(command + ' > /dev/null 2> /dev/null')
    try :
        size = os.path.getsize(file)
        if size < minsize:
            return (1, file)
        else:
            return (0, file)
    except:
        return (-1, file)
 
def genthumb(name, file):
    im = Image.open(file)
    target = thumbdir + '/' + name + '.jpg'
    width, height = im.size
    newheight = int(math.ceil(width * (float(thumbsize[1]) / float(thumbsize[0]))))
    box = (0, 0, width, newheight)
    croped = im.crop(box)
    croped.thumbnail(thumbsize, Image.ANTIALIAS)
    croped.save(target, 'JPEG')
    return target
 
def writeresult(name, file):
    lock = threading.RLock()
    lock.acquire()
    csvhandle.write(name + ',' + file + "\n")
    csvhandle.flush()
    lock.release()
 
class FetchWorker(threading.Thread):
    def __init__(self, name, queue, fails):
        threading.Thread.__init__(self)
        self.queue = queue
        self.fails = fails
        self.start()
    def run(self):
        while True:
            if self.queue.empty():
                break
            (name, url, retry) = self.queue.get()
            if retry <= retrytimes:
                print(self.name + ' is now processing: ' + name + ' [' + url + ']; time: ' + str(retry) + '; in queue left: ' + str(self.queue.qsize()))
                (stat, file) = fetch(name, url)
                if stat == 0:
                    print(self.name + ' ' + file + ' created')
                    print(self.name + ' ' + genthumb(name, file) + ' created')
                    writeresult(name, file)
                else:
                    if retry + 1 <= retrytimes:
                        if stat == 1:
                            print(self.name + ' ' + file + ' created, but maybe too small for a website snapshot, retry for ' + str(retry + 1) + '(th|st|nd) time')
                        elif stat == -1:
                            print(self.name + ' ' + url + ' timeout, retry for ' + str(retry + 1) + '(th|st|nd) time')
                        self.queue.put((name, url, retry + 1))
                self.queue.task_done()
            else:
                self.fails.append((name, url))
                self.queue.task_done()                
 
if __name__ == '__main__':
    if not os.path.exists(cutycapt):
        print('CutyCapt was not found at ' + cutycapt)
        exit(0)
    try:
        os.path.exists(shotsdir) or os.mkdir(shotsdir)
        os.path.exists(thumbdir) or os.mkdir(thumbdir)
    except OSError:
        print('Snapshot or thumbnail dir cannot be created')
    try:
        csvhandle = open(resultcsv, 'w')
        csvhandle.write("name, file\n")
    except:
        print('result file could not be write in, check permission')
    list = getSiteList()
    count = len(list)
    queue = Queue.Queue()
    fails = []
    for i, (name, url) in enumerate(list):
        queue.put((name, url, 1))
    for i in range(tasks):
        threadName = 'Thread' + str(i)
        FetchWorker(threadName, queue, fails)
        time.sleep(1)
    queue.join()
    csvhandle.close()
    print('all done. check ' + resultcsv + ' for result')