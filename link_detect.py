#! /usr/bin/env python
# -*- coding: utf-8 -*-

# 打印ICMP类型的流量包

from scapy.all import *
import time
import logging
import ip_number

class LinkMonk:
    '''
    http://www.rfc-editor.org/rfc/rfc7042.txt
    '''

    data = {
            (0, 0): 'echo reply',
            (3, 0): 'destination unreachable(net unreachable)',
            (3, 1): 'destination unreachable(host unreachable)',
            (3, 2): 'destination unreachable(protocol unreachable)',
            (3, 3): 'destination unreachable(port unreachable)',
            (3, 4): 'destination unreachable(fragmentation needed and DF set)',
            (3, 5): 'destination unreachable(source route failed)',
            (4, 0): 'source quench',
            (5, 0): 'redirect(Redirect datagrams for the Network)',
            (5, 1): 'redirect(datagrams for the Host)',
            (5, 2): 'redirect(Redirect datagrams for the Type of Service and Network)',
            (5, 3): 'redirect(datagrams for the Type of Service and Host)',
            (8, 0): 'echo',
            (11, 0): 'time exceeded(time to live exceeded in transit)',
            (11, 1): 'time exceeded(fragment reassembly time exceeded)',
            (12, 0): 'parameter problem(pointer indicates the error)',
            (13, 0): 'timestamp',
            (14, 0): 'timestamp reply',
            (15, 0): 'information request',
            (16, 0): 'information reply'}

logger = logging.getLogger('main')
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
logger.setLevel(logging.DEBUG)

def process(x):
    Type = x[ICMP].type
    Code = x[ICMP].code
    src = x[IP].src
    dst = x[IP].dst
    logger.info(src + '\t->\t' + dst + '\t' + IcmpMonk.data[(Type, Code)])

def main():
    sniff(prn=lambda x: process(x), lfilter=lambda x: x.haslayer(ICMP))

if __name__ == "__main__":
    logger.info('sniff packet......')
    main()
