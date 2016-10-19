#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2015-2016 clowwindy, Toufukun
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
import time
import datetime

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='See README')
    parser.add_argument('-c', '--count', default=3, type=int,
                        help='with how many failure times it should be '
                             'considered as an attack')
    parser.add_argument('-s', '--ipquerysource', default='ip-api',
                        choices=['ip138','taobao','ip-api'],
                        help='IP geolocation information source')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--exclude', help='IP addresses or '
                        'geolocations that match this pattern will be '
                        'ignored, or not be banned')
    group.add_argument('-m', '--match', help='only IP addresses or '
                        'geolocations that match this pattern will be '
                        'banned')
    group.add_argument('-i', '--interactive', action='store_true',
                        help='interactive mode (You have to confirm '
                        'every IP address this utility bans.)')
    parser.add_argument('--delay', default=600, type=int,
                        help='gap between two geolocation requests '
                        'in milliseconds')
    parser.add_argument('logpath',default='/var/log/shadowsocks.log',
                        help='path to the log file',nargs='?')
    config = parser.parse_args()
    ips = {}
    banned = set()
    last_time = datetime.datetime.now()
    iptables_config = []
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
            geo=ip+' unknown'
            if ip not in banned and ips[ip] >= config.count:
                banned.add(ip)
                try:
                    if (datetime.datetime.now()-last_time).microseconds<config.delay*1000:
                        time.sleep(config.delay/1000.0)
                    if config.ipquerysource=='taobao':
                        req=urllib2.Request('http://ip.taobao.com/service/getIpInfo.php?ip='+ip)
                        info=json.loads(urllib2.urlopen(req).read())['data']
                        geo=' '.join([ip,info['country'],info['region'],info['city']])
                        print(geo,'Y(Enter)/N?',end='')
                    elif config.ipquerysource=='ip138':
                        req=urllib2.Request('http://test.ip138.com/query/?ip='+ip)
                        info=','.join(json.loads(urllib2.urlopen(req).read())['data'])
                        geo=' ',join([ip,info])
                        print(geo,'Y(Enter)/N?',end='')
                    elif config.ipquerysource=='ip-api':
                        req=urllib2.Request('http://ip-api.com/json/'+ip)
                        info=json.loads(urllib2.urlopen(req).read())
                        geo=' '.join([ip,info['country'],info['regionName'],info['city'],info['isp']])
                        print(geo,'Y(Enter)/N?',end='')
                    else:
                        # geo=ip+' unknown'
                        print('the IP location source is not supported')
                        raise Exception()
                except Exception, e:
                    print(repr(e))
                    print(ip,'cannot get ip information','Y(Enter)/N?',)
                choice=False
                if config.interactive:
                    choice=raw_input()
                    if choice.strip()=='' or choice.strip().upper()=='Y':
                        choice=True
                elif config.exclude:
                    if not re.search(config.exclude,geo,re.I):
                        choice=True
                elif config.match:
                    if re.search(config.match,geo,re.I):
                        choice=True
                else:
                    choice=True
                if choice==True:
                    if not config.interactive:
                        print('YES')
                    # banned.add(ip)
                    cmd = 'iptables -A INPUT -s %s -j DROP' % ip
                    print(cmd, file=sys.stderr)
                    sys.stderr.flush()
                    os.system(cmd)
                    iptables_config += ['-A INPUT -s %s -j DROP' % ip]
                else:
                    if not config.interactive: print()
    print()
    print('----- BEGINNING OF IPTABLES CONFIG -----')
    for line in iptables_config: print(line)
    print('-------- END OF IPTABLES CONFIG --------')
