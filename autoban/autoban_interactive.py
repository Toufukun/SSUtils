#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import argparse
import re
import urllib
import urllib2
import json

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='See README')
    parser.add_argument('-c', '--count', default=3, type=int,
                        help='with how many failure times it should be '
                             'considered as an attack')
    parser.add_argument('-s', '--ipquerysource', default='taobao', 
                        choices=['ip138','taobao'],
                        help='IP geolocation information source')
    parser.add_argument('logpath',default='/var/log/shadowsocks.log',
                        help='path to the log file',nargs='?')
    config = parser.parse_args()
    ips = {}
    banned = set()
    for line in open(config.logpath):
        if 'can not parse header when' in line:
            ip = re.search(r'\d+\.\d+\.\d+\.\d+',line).group(0)
            ipv6 = re.search(r'from ([\.:0-9a-fA-F]+)',line).group(1)
            if ip not in ips:
                ips[ip] = 1
                print(ip)
                sys.stdout.flush()
            else:
                ips[ip] += 1
            if ip not in banned and ips[ip] >= config.count:
                banned.add(ip)
                try:
                    if config.ipquerysource=='taobao':
                        req=urllib2.Request('http://ip.taobao.com/service/getIpInfo.php?ip='+ip)
                        info=json.loads(urllib2.urlopen(req).read())['data']
                        print(ip,info['country'],info['region'],info['city'],'Y(Enter)/N?',)
                    elif config.ipquerysource=='ip138':
                        req=urllib2.Request('http://test.ip138.com/query/?ip='+ip)
                        info=','.join(json.loads(urllib2.urlopen(req).read())['data'])
                        print(ip,info,'Y(Enter)/N?')
                    else:
                        print('the IP location source is not supported')
                        raise Exception()
                except:
                    print(ip,'cannot get ip information','Y(Enter)/N?',)
                choice=raw_input()
                if choice.strip()=='' or choice.strip().upper()=='Y':
                    # banned.add(ip)
                    cmd = 'iptables -A INPUT -s %s -j DROP' % ip
                    print(cmd, file=sys.stderr)
                    sys.stderr.flush()
                    os.system(cmd)
