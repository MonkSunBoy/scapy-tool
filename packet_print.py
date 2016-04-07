#! /usr/bin/env python

from scapy.all import *
import time
import os
import logging
import ip_number

logger = logging.getLogger('main')
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
logger.setLevel(logging.DEBUG)

static_dict = {}

def format(x):
    if hasattr(x, 'type'):
        if hex(x.type) == '0x800':
            format_ip(x)
    else:
        format_other(x)

def format_other(x):
    pass

def format_ip(x):
    ip_protocol = x[IP].proto
    ip_src = x[IP].src
    ip_dst = x[IP].dst
    if (ip_src, ip_dst, ip_protocol) in static_dict:
        static_dict[(ip_src, ip_dst, ip_protocol)] += 1
    else:
        static_dict[(ip_src, ip_dst, ip_protocol)] = 1

    sort = sorted(static_dict.items(),key=lambda e:e[1])
    for item in sort:
        print item

    print('=' * 30)

def main():
    sniff(prn=lambda x: format(x), filter='arp')

if __name__ == "__main__":
    logger.info('sniff packet......')
    main()

