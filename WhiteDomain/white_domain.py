#!/usr/bin/python
# encoding: utf-8

import csv
from sql_command import Database
import datetime


def get_domain():

    csvfile = file('top-1m.csv', 'r')
    reader = csv.reader(csvfile)
    domain_list = [domain[1] for domain in reader]
    csvfile.close()
    return domain_list


def difference_domain():

    domain_list = []
    exist_domain = []
    existe_domain_temp = ()
    domain_list = get_domain()

    if not domain_list:
        print 'Domain_list is empty'
        return
    db = Database()
    existe_domain_temp = db.existed_white_domain()
    if existe_domain_temp:
        exist_domain = [i[0] for i in existe_domain_temp]

    db.close_db()
    # print len(list(set(domain_list).difference(set(exist_domain))))
    return list(set(domain_list).difference(set(exist_domain)))


def update_domain_white_list():

    domain_list = []
    domain_list = difference_domain()
    print str(len(domain_list)) + ' will be inserted'
    if domain_list:
        db = Database()
        db.insert_domain_white_list(domain_list)
        db.close_db()

if __name__ == '__main__':

    print 'starting...'
    starttime = datetime.datetime.now()
    update_domain_white_list()
    endtime = datetime.datetime.now()
    print '运行时间:' + str((endtime - starttime).seconds)
