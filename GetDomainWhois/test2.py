#!/usr/bin/python
#encoding:utf-8

from BeautifulSoup import BeautifulSoup
import re


def extract_domain_whois(path =''):

    pattern_email = re.compile(r'<span id="email">.*')
    pattern_regname = re.compile(r'<span id="regname">.*')
    pattern_regorg = re.compile(r'<span id="regorg">.*')

    if not path:
        return
    try:
        fr = open(path, 'r')
    except:
        print 'can not open the file'
        return 

    content = fr.readlines()

    for line in content:
        match = pattern_email.findall(line)
        if match:

            soup = BeautifulSoup(match[0])
            print soup.find('span').string

        match = pattern_regname.findall(line)
        if match:
            soup = BeautifulSoup(match[0])
            print soup.find('span').string

        match = pattern_regorg.findall(line)
        if match:
            soup = BeautifulSoup(match[0])
            print soup.find('span').string

    fr.close()



def main():
    
    path = 'htm1.txt'
    extract_domain_whois(path)



if __name__ == '__main__':
    main()