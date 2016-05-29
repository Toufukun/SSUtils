#!/usr/bin/env python3
#coding=utf-8
#
#
#https://www.logcg.com

import urllib3
import re
import datetime
import certifi
import codecs
import base64


def getList(listUrl):
    http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED',  # Force certificate check.
        ca_certs=certifi.where(),  # Path to the Certifi bundle.
    )

    data = http.request('GET', listUrl, timeout=10).data
    return data

def whiteListCheck():
    dnsmasq_china_list = base64.b64decode(b'aHR0cHM6Ly9naXRodWIuY29tL1IwdXRlci9nZndfZG9tYWluX3doaXRlbGlzdC9yYXcvbWFzdGVyL3doaXRlbGlzdENhY2hl').decode('ascii')
    try:
        print('Getting white list...')
        content = getList(dnsmasq_china_list)
        content = content.decode('utf-8')
        f = codecs.open('./list/whitelist', 'w', 'utf-8')
        f.write(content)
        f.close()
    except:
        print('Get list update failed,use cache to update instead.')


    # domainList = []
    whitelist = codecs.open('./list/whitelist','r','utf-8')
    whitelistTxt = codecs.open('./list/whitelist.txt','w','utf-8')
    whitelistTxt.write('// updated on ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S" + '\n'))
    # Write list
    for line in whitelist.readlines():
        
        domain = re.findall(r'\w+\.\w+', line)
        if len(domain) > 0:
        # domainList.append(domain[0])
            whitelistTxt.write('DOMAIN-SUFFIX,%s,ChinaProxy\n'%(domain[0]))


    whitelist.close()
    whitelistTxt.close()



def getCertifiedList():
    # the url of certifiedlist
    baseurl = base64.b64decode(b'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2dmd2xpc3QvZ2Z3bGlzdC9tYXN0ZXIvZ2Z3bGlzdC50eHQ=').decode('ascii')

    comment_pattern = '^\!|\[|^@@|^\d+\.\d+\.\d+\.\d+'
    domain_pattern = '([\w\-\_]+\.[\w\.\-\_]+)[\/\*]*'

    tmpfile = './list/tmp'

    certifiedListTxt = codecs.open('./list/certifiedlist.txt', 'w', 'utf-8')
    certifiedListTxt.write('// SS config file for SR with certified list \n')
    certifiedListTxt.write('// updated on ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '\n')
    certifiedListTxt.write('\n')

    try:

        data = getList(baseurl)

        content = codecs.decode(data, 'base64_codec').decode('utf-8')

        # write the decoded content to file then read line by line
        tfs = codecs.open(tmpfile, 'w', 'utf-8')
        tfs.write(content)
        tfs.close()
        print('Certified list fetched, writing...')
    except:
        print('Certified list fetch failed, use tmp instead...')
    tfs = codecs.open(tmpfile, 'r', 'utf-8')

    # Store all domains, deduplicate records
    domainList = []

    # Write list
    for line in tfs.readlines():

     if re.findall(comment_pattern, line):
         continue
     else:
         domain = re.findall(domain_pattern, line)
         if domain:
             try:
                 found = domainList.index(domain[0])
             except ValueError:
                 domainList.append(domain[0])
                 certifiedListTxt.write('DOMAIN-SUFFIX,%s,Proxy,force-remote-dns\n' % (domain[0]))
         else:
             continue

    tfs.close()
    certifiedListTxt.close()


def getAdList():
    # get list to block most of ads .
    # the url of  https://gist.github.com/iyee/2e27c124af2f7a4f0d5a
    outfile = './list/adlist.txt'
    tmpfile = './list/adtmp'
    baseurl = 'https://gist.githubusercontent.com/raw/2e27c124af2f7a4f0d5a/main.conf'

    comment_pattern = '^\!|\[|^@@|\/|http|\#|\*|\?|\_|^\.|^\d+\.\d+\.\d+\.\d+'
    domain_pattern = '(\#?[\w\-\_]+\,[\/\w\.\-\_]+\,REJECT)[\/\*]*'

    fs = codecs.open(outfile, 'w', 'utf-8')
    fs.write('// thx  https://gist.github.com/iyee/2e27c124af2f7a4f0d5a \n')
    fs.write('// updated on ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '\n')
    fs.write('\n')


    try:

        content = getList(baseurl).decode('utf-8')

        # write the content to file then read line by line
        if len(content) < 100:
            raise FileNotFoundError
        tfs = codecs.open(tmpfile, 'w', 'utf-8')
        tfs.write(content)
        tfs.close()
        print('adlist fetched, writing...')
    except:
        print('adlist fetch failed, use tmpfile instead...')
    # Store all domains, deduplicate records
    domainlist = []

    # Write list
    tfs = codecs.open(tmpfile, 'r', 'utf-8')
    for line in tfs.readlines():

        if re.findall(comment_pattern, line):
            continue
        else:
            domain = re.findall(domain_pattern, line)
            if domain:
                try:
                    found = domainlist.index(domain[0])
                except ValueError:
                    domainlist.append(domain[0])
                    fs.write(domain[0] + '\n')
            else:
                continue

    tfs.close()
    fs.close()


def genCertifiedConf(ifp='template/ss_certifiedlist_conf',ofp='configFileHere/certifiedlist.conf'):
    f = codecs.open(ifp, 'r','utf-8')
    certifiedlist = codecs.open('list/certifiedlist.txt', 'r','utf-8')
    adlist = codecs.open('list/adlist.txt', 'r','utf-8')
    proxy = codecs.open('ServerConfig.txt', 'r', 'utf8')
    file_content = f.read()
    adlist_buffer = adlist.read()
    certifiedlist_buffer = certifiedlist.read()
    proxy_buffer = proxy.read()
    certifiedlist.close()
    adlist.close()
    f.close()
    proxy.close()

    file_content = file_content.replace('__ADBLOCK__', adlist_buffer)
    file_content = file_content.replace('__CERTIFIEDLIST__', certifiedlist_buffer)
    file_content = file_content.replace('__Proxy__', proxy_buffer)

    confs = codecs.open(ofp, 'w','utf-8')
    confs.write(file_content)
    confs.close()


def genWhiteConf():
    whiteListCheck()
    cfs = codecs.open('template/ss_whitelist_conf', 'r','utf-8')
    certifiedlist = codecs.open('list/whitelist.txt', 'r','utf-8')
    adlist = codecs.open('list/adlist.txt', 'r','utf-8')
    proxy = codecs.open('ServerConfig.txt','r','utf8')
    file_content = cfs.read()
    adlist_buffer = adlist.read()
    certifiedlist_buffer = certifiedlist.read()
    proxy_buffer = proxy.read()
    certifiedlist.close()
    adlist.close()
    cfs.close()
    proxy.close()

    file_content = file_content.replace('__ADBLOCK__', adlist_buffer)
    file_content = file_content.replace('__CERTIFIEDWHITELIST__', certifiedlist_buffer)
    file_content = file_content.replace('__Proxy__', proxy_buffer)

    confs = codecs.open('configFileHere/whitelist.conf', 'w','utf-8')
    confs.write(file_content)
    confs.close()

def main():
    print('Getting certified list...')
    getCertifiedList()
    print('Getting AD list...')
    getAdList()

    print ('Generate config file: certifiedlist.conf')
    genCertifiedConf()
    genCertifiedConf(ifp='template/ss_certifiedlist_sradb_conf',ofp='configFileHere/certifiedlist_sradb.conf')
    genCertifiedConf(ifp='template/ss_certifiedlist_noadb_conf',ofp='configFileHere/certifiedlist_noadb.conf')
    print ('Generate config file: whitelist.conf')
    genWhiteConf()
    print ('All done!')
    print('Now you need edit config file to add your server infomation.')

if __name__ == '__main__':
    main()