#! /usr/bin/env python
# -*- coding: utf-8 -*-

# 打印ARP应答的包记录，发现ARP欺骗
# http://www.rfc-editor.org/rfc/rfc826.txt

from scapy.all import *
import time
import logging
import ip_number

logger = logging.getLogger('main')
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
logger.setLevel(logging.DEBUG)

def process(x):

    if x[ARP].op  == 2:
        hwsrc = x[ARP].hwsrc
        psrc  = x[ARP].psrc
        hwdst = x[ARP].hwdst
        pdst  = x[ARP].pdst

        logger.info(psrc + '(' + hwsrc + ')' + '\t->\t' + pdst + '(' + hwdst + ')')

def main():
    sniff(prn=lambda x: process(x), lfilter=lambda x: x.haslayer(ARP))

if __name__ == "__main__":
    logger.info('sniff packet......')
    main()

