#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import configloader
import importloader
import cymysql
import subprocess
import socket
import threading
from shadowsocks import common, shell

class TCPing():
    def __init__(self):
        self.status = []
        self.checkList = [
            ('www.foshan.gov.cn',80),
            ('www.sz.gov.cn',80),
            ('www.gz.gov.cn',80)
        ]

    def clearStatus(self):
        if self.status != []:
            self.status = []

    def tcping(self, ip_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t_start = round(time.time()*1000)
        try:
            s.settimeout(1)
            s.connect(ip_port)
            s.shutdown(socket.SHUT_RD)
            t_end = round(time.time()*1000)
            s.settimeout(None)
            self.status.append(-1)
            # print( (t_end-t_start), "ms" )
            # s.close()
        except Exception as e:
            s.settimeout(None)
            self.status.append(1)
            # print('[failed] timeout')

    def blocked(self, checkList):
        if not checkList:
            checkList = self.checkList
        for num in range(len(checkList)):
            t = threading.Thread( target=self.tcping, args=[checkList[num]] )
            t.start()
        while True:
            if len(self.status)==len(checkList):
                break
        j = 0
        for i in self.status:
            if i == 1:
                j = j+1
        self.clearStatus()
        if j == len(checkList):
            return True
        return False

class Nettest(object):

    def __init__(self):
        self.event = threading.Event()
        self.has_stopped = False
        self.blocked = None
        self.blocked_changed = False
        self.dnsLogPath = os.path.abspath(os.getcwd())  + '/dns.log'
        self.TCPing = TCPing()

    def nettest_thread(self):
        if self.event.wait(1):
            return

        logging.info("Nettest starting...You can't stop right now!")

        if configloader.get_config().MYSQL_SSL_ENABLE == 1:
            conn = cymysql.connect(
                host=configloader.get_config().MYSQL_HOST,
                port=configloader.get_config().MYSQL_PORT,
                user=configloader.get_config().MYSQL_USER,
                passwd=configloader.get_config().MYSQL_PASS,
                db=configloader.get_config().MYSQL_DB,
                charset='utf8',
                ssl={
                    'ca': configloader.get_config().MYSQL_SSL_CA,
                    'cert': configloader.get_config().MYSQL_SSL_CERT,
                    'key': configloader.get_config().MYSQL_SSL_KEY})
        else:
            conn = cymysql.connect(
                host=configloader.get_config().MYSQL_HOST,
                port=configloader.get_config().MYSQL_PORT,
                user=configloader.get_config().MYSQL_USER,
                passwd=configloader.get_config().MYSQL_PASS,
                db=configloader.get_config().MYSQL_DB,
                charset='utf8')
        conn.autocommit(True)

        def getTcpingList():
            cur = conn.cursor()
            cur.execute("SELECT `id`,`ip`,`port` FROM `test_ip` WHERE `ip` != '' LIMIT 3")
            n=[]
            for r in cur.fetchall():
                r = list(r)
                n.append( (r[1],int(r[2])) )
            cur.close()
            return n

        def set_block_status():
            if self.blocked is None:
                cur = conn.cursor()
                cur.execute("SELECT `blocked` FROM `ss_node` where `id` = '" + str(configloader.get_config().NODE_ID) + "'")
                temp = cur.fetchone()
                if temp[0] == 1:
                    self.blocked = True
                else:
                    self.blocked = False
                cur.close()

        def check_and_update():
            checkList = getTcpingList()
            set_block_status()
            if self.blocked == True:
                if not self.TCPing.blocked(checkList):
                    time.sleep(2)
                    if not self.TCPing.blocked(checkList):
                        time.sleep(2)
                        if not self.TCPing.blocked(checkList):
                            self.blocked = False
                            self.blocked_changed = True
            else:
                if self.TCPing.blocked(checkList):
                    time.sleep(2)
                    if self.TCPing.blocked(checkList):
                        time.sleep(2)
                        if self.TCPing.blocked(checkList):
                            self.blocked = True
                            self.blocked_changed = True

        def checkDnsFileSize():
            if os.path.isfile(self.dnsLogPath):
                fsize = os.path.getsize(self.dnsLogPath)
                if fsize > 50 * 1024 * 1024:
                    open(self.dnsLogPath, 'w').close()
                    logging.info("dns log file reached size limit, now resized to zero")
            else:
                open(self.dnsLogPath, 'w').close()
                logging.info("create dns log file")

        checkDnsFileSize()
        check_and_update()
        if self.blocked_changed == True:
            cur = conn.cursor()
            if self.blocked == True:
                logging.info("Blocked")
                cur.execute("UPDATE `ss_node` SET `blocked` = '1' where `id` = '" + str(configloader.get_config().NODE_ID) + "'")
            else:
                logging.info("Unblocked")
                cur.execute("UPDATE `ss_node` SET `blocked` = '0' where `id` = '" + str(configloader.get_config().NODE_ID) + "'")
            cur.close()
            conn.close()
            self.blocked_changed = False

        logging.info("Nettest finished!")

    @staticmethod
    def thread_db(obj):

        if configloader.get_config().NETTEST == 0:
            return

        if configloader.get_config().API_INTERFACE == 'modwebapi':
            import webapi_utils

            global webapi
            webapi = webapi_utils.WebApi()

        global db_instance
        db_instance = obj()

        try:
            while True:
                try:
                    db_instance.nettest_thread()
                except Exception as e:
                    import traceback
                    trace = traceback.format_exc()
                    logging.error(trace)
                    #logging.warn('db thread except:%s' % e)
                if db_instance.event.wait(configloader.get_config().NETTEST*60):
                    break
                if db_instance.has_stopped:
                    break
        except KeyboardInterrupt as e:
            pass
        db_instance = None

    @staticmethod
    def thread_db_stop():
        global db_instance
        db_instance.has_stopped = True
        db_instance.event.set()
