#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import socket
from server_pool import ServerPool
import traceback
from transfer_utils import *
from shadowsocks import common, shell, lru_cache
from configloader import load_config, get_config
import importloader
import platform
import datetime
import fcntl
from copy import copy
import cymysql

import constants

switchrule = None
db_instance = None


class DbTransfer(object):

    def __init__(self):
        import threading
        self.last_update_transfer = {}
        self.event = threading.Event()
        # 通过端口存储用户id
        self.port_uid_table = {}
        # 通过用户id存储端口
        self.uid_port_table = {}
        # 通过用户id存储流量包id
        self.uid_productid_table = {}
        self.node_speedlimit = 0.00
        self.traffic_rate = 0.0

        self.detect_text_list_all = {}
        self.detect_text_all_ischanged = False
        self.detect_hex_list_all = {}
        self.detect_hex_all_ischanged = False
        self.detect_text_list_dns = {}
        self.detect_text_dns_ischanged = False
        self.detect_hex_list_dns = {}
        self.detect_hex_dns_ischanged = False

        self.mu_only = False
        self.is_relay = False

        self.relay_type = constants.RELAY_NO
        self.relay_to_id = 0
        self.common_relay_rule = None

        self.relay_rule_list = {}
        self.node_ip_list = []
        self.mu_port_list = []

        self.has_stopped = False

        self.enable_dnsLog = True

        self.traffic_log_to_insert = ""
        self.traffic_log_query_head = "INSERT INTO `user_traffic_log` (`id`, `user_id`, `u`, `d`, `node_id`, `rate`, `traffic`, `log_time`) VALUES "

        self.alive_ip_to_insert = ""
        self.alive_ip_query_head = "INSERT INTO `alive_ip` (`id`, `nodeid`,`userid`, `ip`, `datetime`) VALUES "

        self.MYSQL_HOST = get_config().MYSQL_HOST
        self.MYSQL_PORT = get_config().MYSQL_PORT
        self.MYSQL_USER = get_config().MYSQL_USER
        self.MYSQL_PASS = get_config().MYSQL_PASS
        self.MYSQL_DB = get_config().MYSQL_DB

        self.MYSQL_SSL_ENABLE = get_config().MYSQL_SSL_ENABLE
        self.MYSQL_SSL_CA = get_config().MYSQL_SSL_CA
        self.MYSQL_SSL_CERT = get_config().MYSQL_SSL_CERT
        self.MYSQL_SSL_KEY = get_config().MYSQL_SSL_KEY

        self.PORT_GROUP = get_config().PORT_GROUP
        self.ENABLE_DNSLOG = get_config().ENABLE_DNSLOG
        self.NODE_ID = get_config().NODE_ID
        self.CLOUDSAFE = get_config().CLOUDSAFE

        self.mysql_conn = None
        self.mysql_err_sleep = 10

    def getMysqlConnBase(self):
        if self.MYSQL_SSL_ENABLE == 1:
            conn = cymysql.connect(
                host=self.MYSQL_HOST,
                port=self.MYSQL_PORT,
                user=self.MYSQL_USER,
                passwd=self.MYSQL_PASS,
                db=self.MYSQL_DB,
                charset='utf8',
                ssl={
                    'ca': self.MYSQL_SSL_CA,
                    'cert': self.MYSQL_SSL_CERT,
                    'key': self.MYSQL_SSL_KEY},
                connect_timeout=120)
        else:
            conn = cymysql.connect(
                host=self.MYSQL_HOST,
                port=self.MYSQL_PORT,
                user=self.MYSQL_USER,
                passwd=self.MYSQL_PASS,
                db=self.MYSQL_DB,
                charset='utf8',
                connect_timeout=120)
        conn.autocommit(True)
        return conn

    def getMysqlConn(self):
        if self.mysql_conn is None:
            self.mysql_conn = self.getMysqlConnBase()
        return self.mysql_conn

    def closeMysqlConn(self):
        if self.mysql_conn is not None:
            logging.debug("close mysql conn")
            self.mysql_err_sleep = 10
            try:
                self.mysql_conn.close()
            except:
                pass
            self.mysql_conn = None

    def isMysqlConnectable(self):
        failed = 0
        for i in range(2):
            if G_socket_ping((self.MYSQL_HOST, self.MYSQL_PORT)) == -1:
                failed = failed + 1
        if failed == 2:
            return False
        return True

    def waitForMysqlConnectable(self):
        tcp_sleep = 5
        while self.isMysqlConnectable() is False:
            tcp_sleep += tcp_sleep
            time.sleep(tcp_sleep)

    def getMysqlCur(self, query_sql, fetchone=False, fetchall=False, no_result=False):
        try:
            ret = None
            cur = None
            conn = self.getMysqlConn()
            cur = conn.cursor()
            cur.execute(query_sql)
            if fetchall is True and fetchone is False:
                ret = cur.fetchall()
            if fetchall is False and fetchone is True:
                ret = cur.fetchone()
            if ret:
                return ret
            if fetchall is True and fetchone is False:
                return {}
        except ConnectionAbortedError as e:
            logging.error(e)
            logging.error(query_sql)
            # print(isinstance(e, ConnectionAbortedError))

            self.waitForMysqlConnectable()
            time.sleep(self.mysql_err_sleep)
            self.mysql_err_sleep += 10

            if cur:
                cur.close()
            return self.getMysqlCur(
                query_sql,
                fetchone=fetchone,
                fetchall=fetchall,
                no_result=no_result)
        except Exception as e:
            logging.error(e)
            logging.error(query_sql)

            # BrokenPipeError 无法直接catch
            if hasattr(e, 'errmsg'):
                """
                print(
                    e.errmsg,
                    type(e.errmsg),
                    isinstance(e.errmsg, BrokenPipeError))
                print(
                    e,
                    type(e),
                    isinstance(e, ConnectionAbortedError),
                    isinstance(e.errmsg, ConnectionAbortedError))
                """
                if isinstance(e.errmsg, BrokenPipeError) or \
                    isinstance(e.errmsg, ConnectionAbortedError) or \
                    isinstance(e.errmsg, BlockingIOError):
                    self.waitForMysqlConnectable()
                    time.sleep(self.mysql_err_sleep)
                    self.closeMysqlConn()

                    if cur:
                        cur.close()
                    return self.getMysqlCur(
                        query_sql,
                        fetchone=fetchone,
                        fetchall=fetchall,
                        no_result=no_result)

            self.waitForMysqlConnectable()
            time.sleep(self.mysql_err_sleep)
            self.mysql_err_sleep += 10

            if cur:
                cur.close()
            return self.getMysqlCur(
                query_sql,
                fetchone=fetchone,
                fetchall=fetchall,
                no_result=no_result)
        return None

    def append_traffic_log(self, pid, dt_transfer):
        traffic_show = G_traffic_show(
            (dt_transfer[pid][0] + dt_transfer[pid][1]) * self.traffic_rate)
        if self.traffic_log_to_insert:
            self.traffic_log_to_insert += ","
        self.traffic_log_to_insert += "(NULL, '" + \
                str(self.port_uid_table[pid]) + \
                "', '" + \
                str(dt_transfer[pid][0]) + \
                "', '" + \
                str(dt_transfer[pid][1]) + \
                "', '" + \
                str(self.NODE_ID) + \
                "', '" + \
                str(self.traffic_rate) + \
                "', '" + \
                traffic_show + \
                "', unix_timestamp())"

    def mass_insert_traffic(self):
        if self.traffic_log_to_insert:
            query_sql = self.traffic_log_query_head + self.traffic_log_to_insert + ";"
            self.getMysqlCur(query_sql, no_result=True)
            self.traffic_log_to_insert = ""

    def append_alive_ip(self, pid, ip):
        if self.alive_ip_to_insert:
            self.alive_ip_to_insert += ","
        self.alive_ip_to_insert += "(NULL, '" + \
            str(self.NODE_ID) + "','" + str(self.port_uid_table[pid]) + "', '" + str(ip) + "', unix_timestamp())"

    def mass_insert_alive_ip(self):
        if self.alive_ip_to_insert:
            query_sql = self.alive_ip_query_head + self.alive_ip_to_insert + ";"
            self.getMysqlCur(query_sql, no_result=True)
            self.alive_ip_to_insert = ""

    def update_all_user(self, dt_transfer):
        update_transfer = {}

        # 同一用户可有多个产品，故以产品id为线索更新流量
        query_head = 'UPDATE user_product_traffic'
        query_sub_when = ''
        query_sub_when2 = ''
        query_sub_in = None

        alive_user_count = 0
        bandwidth_thistime = 0

        # conn = self.getMysqlConn()

        for id in dt_transfer.keys():
            if dt_transfer[id][0] == 0 and dt_transfer[id][1] == 0:
                continue

            if self.uid_productid_table[self.port_uid_table[id]] == -1:
                logging.debug('self.uid_productid_table[self.port_uid_table[id]] == -1')
                continue

            query_sub_when += ' WHEN %s THEN traffic_flow_used_up+%s' % (
                self.uid_productid_table[self.port_uid_table[id]],
                dt_transfer[id][0] * self.traffic_rate)
            query_sub_when2 += ' WHEN %s THEN traffic_flow_used_dl+%s' % (
                self.uid_productid_table[self.port_uid_table[id]],
                dt_transfer[id][1] * self.traffic_rate)
            update_transfer[id] = dt_transfer[id]

            alive_user_count = alive_user_count + 1

            self.append_traffic_log(id, dt_transfer)

            bandwidth_thistime = bandwidth_thistime + \
                (dt_transfer[id][0] + dt_transfer[id][1])

            if query_sub_in is not None:
                query_sub_in += ',%s' % self.uid_productid_table[self.port_uid_table[id]]
            else:
                query_sub_in = '%s' % self.uid_productid_table[self.port_uid_table[id]]
        self.mass_insert_traffic()

        if query_sub_when != '':
            query_sql = query_head + ' SET traffic_flow_used_up = CASE id' + query_sub_when + \
                ' END, traffic_flow_used_dl = CASE id' + query_sub_when2 + \
                ' END, last_use_time = unix_timestamp() ' + \
                ' WHERE id IN (%s)' % query_sub_in

            self.getMysqlCur(query_sql, no_result=True)

        query_sql = "UPDATE `ss_node` SET `node_heartbeat`=unix_timestamp(),`node_bandwidth`=`node_bandwidth`+'" + \
            str(bandwidth_thistime) + \
            "' WHERE `id` = " + str(self.NODE_ID) + " ; "
        self.getMysqlCur(query_sql, no_result=True)

        query_sql = "INSERT INTO `ss_node_online_log` (`id`, `node_id`, `online_user`, `log_time`) VALUES (NULL, '" + \
                    str(self.NODE_ID) + "', '" + str(alive_user_count) + "', unix_timestamp()); "
        self.getMysqlCur(query_sql, no_result=True)

        online_iplist = ServerPool.get_instance().get_servers_iplist()
        for pid in online_iplist.keys():
            for ip in online_iplist[pid]:
                self.append_alive_ip(pid, ip)
        self.mass_insert_alive_ip()

        detect_log_list = ServerPool.get_instance().get_servers_detect_log()
        for port in detect_log_list.keys():
            for rule_id in detect_log_list[port]:
                query_sql = "INSERT INTO `detect_log` (`id`, `user_id`, `list_id`, `datetime`, `node_id`) VALUES (NULL, '" +  \
                    str(self.port_uid_table[port]) + "', '" + str(rule_id) + "', UNIX_TIMESTAMP(), '" + str(self.NODE_ID) + "')"
                self.getMysqlCur(query_sql, no_result=True)

        deny_str = ""
        if platform.system() == 'Linux' and get_config().ANTISSATTACK == 1:
            wrong_iplist = ServerPool.get_instance().get_servers_wrong()
            server_ip = socket.gethostbyname(self.MYSQL_HOST)
            for id in wrong_iplist.keys():
                for ip in wrong_iplist[id]:
                    realip = ""
                    is_ipv6 = False
                    if common.is_ip(ip):
                        if(common.is_ip(ip) == socket.AF_INET):
                            realip = ip
                        else:
                            if common.match_ipv4_address(ip) is not None:
                                realip = common.match_ipv4_address(ip)
                            else:
                                is_ipv6 = True
                                realip = ip
                    else:
                        continue

                    if str(realip).find(str(server_ip)) != -1:
                        continue

                    has_match_node = False
                    for node_ip in self.node_ip_list:
                        if str(realip).find(node_ip) != -1:
                            has_match_node = True
                            continue

                    if has_match_node:
                        continue

                    query_sql = "SELECT * FROM `blockip` where `ip` = '" + str(realip) + "'"
                    rows = self.getMysqlCur(query_sql, fetchone=True)

                    if rows is not None:
                        continue
                    if self.CLOUDSAFE == 1:
                        query_sql = "INSERT INTO `blockip` (`id`, `nodeid`, `ip`, `datetime`) VALUES (NULL, '" + \
                            str(self.NODE_ID) + \
                            "', '" + \
                            str(realip) + \
                            "', unix_timestamp())"
                        self.getMysqlCur(query_sql, no_result=True)
                    else:
                        if not is_ipv6:
                            os.system('route add -host %s gw 127.0.0.1' % str(realip))
                            deny_str = deny_str + "\nALL: " + str(realip)
                        else:
                            os.system('ip -6 route add ::1/128 via %s/128' % str(realip))
                            deny_str = deny_str + "\nALL: [" + str(realip) + "]/128"

                        logging.info("Local Block ip:%s", str(realip))
                if self.CLOUDSAFE == 0:
                    deny_file = open('/etc/hosts.deny', 'a')
                    fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
                    deny_file.write(deny_str)
                    deny_file.close()

        return update_transfer

    def uptime(self):
        with open('/proc/uptime', 'r') as f:
            return float(f.readline().split()[0])

    def load(self):
        return os.popen("cat /proc/loadavg | awk '{ print $1\" \"$2\" \"$3 }'").readlines()[0][:-2]

    def push_db_all_user(self):
        # 更新用户流量到数据库
        last_transfer = self.last_update_transfer
        curr_transfer = ServerPool.get_instance().get_servers_transfer()
        # 上次和本次的增量
        dt_transfer = {}
        for id in curr_transfer.keys():
            if id in last_transfer:
                if curr_transfer[id][0] + curr_transfer[id][1] - \
                        last_transfer[id][0] - last_transfer[id][1] <= 0:
                    continue
                if last_transfer[id][0] <= curr_transfer[id][0] and \
                        last_transfer[id][1] <= curr_transfer[id][1]:
                    dt_transfer[id] = [
                        curr_transfer[id][0] - last_transfer[id][0],
                        curr_transfer[id][1] - last_transfer[id][1]]
                else:
                    dt_transfer[id] = [curr_transfer[
                        id][0], curr_transfer[id][1]]
            else:
                if curr_transfer[id][0] + curr_transfer[id][1] <= 0:
                    continue
                dt_transfer[id] = [curr_transfer[id][0], curr_transfer[id][1]]

        for id in dt_transfer.keys():
            last = last_transfer.get(id, [0, 0])
            last_transfer[id] = [last[0] + dt_transfer[id]
                                 [0], last[1] + dt_transfer[id][1]]
        self.last_update_transfer = last_transfer.copy()
        # print(dt_transfer)
        self.update_all_user(dt_transfer)

    def set_detect_rule_list(self):
        # 读取审计规则,数据包匹配部分
        keys_detect = ['id', 'regex', 'match_filed']

        query_sql = "SELECT " + ','.join(keys_detect) + \
                    " FROM detect_list WHERE `type` = 1 AND `match_filed` = 0"
        ret = self.getMysqlCur(query_sql, fetchall=True)

        exist_id_list = []

        for r in ret:
            id = int(r[0])
            exist_id_list.append(id)
            # add new rule
            if id not in self.detect_text_list_all:
                d = {}
                d['id'] = id
                d['regex'] = str(r[1])
                d['match_filed'] = r[2]
                self.detect_text_list_all[id] = d
                self.detect_text_all_ischanged = True
            else:
                # change rule exist
                if r[1] != self.detect_text_list_all[id]['regex']:
                    del self.detect_text_list_all[id]
                    d = {}
                    d['id'] = id
                    d['regex'] = str(r[1])
                    d['match_filed'] = r[2]
                    self.detect_text_list_all[id] = d
                    self.detect_text_all_ischanged = True

        deleted_id_list = []
        for id in self.detect_text_list_all:
            if id not in exist_id_list:
                deleted_id_list.append(id)
                self.detect_text_all_ischanged = True

        for id in deleted_id_list:
            del self.detect_text_list_all[id]

        query_sql = "SELECT " + ','.join(keys_detect) + \
                    " FROM detect_list WHERE `type` = 2 AND `match_filed` = 0"
        ret = self.getMysqlCur(query_sql, fetchall=True)
        exist_id_list = []

        for r in ret:
            id = int(r[0])
            exist_id_list.append(id)
            if r[0] not in self.detect_hex_list_all:
                d = {}
                d['id'] = id
                d['regex'] = str(r[1])
                d['match_filed'] = r[2]
                self.detect_hex_list_all[id] = d
                self.detect_hex_all_ischanged = True
            else:
                if r[1] != self.detect_hex_list_all[r[0]]['regex']:
                    del self.detect_hex_list_all[id]
                    d = {}
                    d['id'] = int(r[0])
                    d['regex'] = str(r[1])
                    d['match_filed'] = r[2]
                    self.detect_hex_list_all[id] = d
                    self.detect_hex_all_ischanged = True

        deleted_id_list = []
        for id in self.detect_hex_list_all:
            if id not in exist_id_list:
                deleted_id_list.append(id)
                self.detect_hex_all_ischanged = True

        for id in deleted_id_list:
            del self.detect_hex_list_all[id]

        query_sql = "SELECT " + ','.join(keys_detect) + \
                    " FROM detect_list where `type` = 1 AND `match_filed` = 1"
        ret = self.getMysqlCur(query_sql, fetchall=True)

        exist_id_list = []

        for r in ret:
            id = int(r[0])
            exist_id_list.append(id)
            # add new rule
            if id not in self.detect_text_list_dns:
                logging.debug('[if id not in self.detect_text_list_dns] add new rule')
                d = {}
                d['id'] = id
                d['regex'] = str(r[1])
                d['match_filed'] = r[2]
                self.detect_text_list_dns[id] = d
                self.detect_text_dns_ischanged = True
            else:
                # change rule exist
                if r[1] != self.detect_text_list_dns[id]['regex']:
                    logging.debug("[if r[1] != self.detect_text_list_dns[id]['regex']]  edit this rule")
                    del self.detect_text_list_dns[id]
                    d = {}
                    d['id'] = id
                    d['regex'] = str(r[1])
                    d['match_filed'] = r[2]
                    self.detect_text_list_dns[id] = d
                    self.detect_text_dns_ischanged = True

        deleted_id_list = []
        for id in self.detect_text_list_dns:
            if id not in exist_id_list:
                deleted_id_list.append(id)
                self.detect_text_dns_ischanged = True

        for id in deleted_id_list:
            logging.debug('del self.detect_text_list_dns[id]')
            del self.detect_text_list_dns[id]

        query_sql = "SELECT " + ','.join(keys_detect) + \
                    " FROM detect_list where `type` = 2 AND `match_filed` = 1"
        ret = self.getMysqlCur(query_sql, fetchall=True)
        exist_id_list = []

        for r in ret:
            id = int(r[0])
            exist_id_list.append(id)
            if r[0] not in self.detect_hex_list_dns:
                d = {}
                d['id'] = id
                d['regex'] = str(r[1])
                d['match_filed'] = r[2]
                self.detect_hex_list_dns[id] = d
                self.detect_hex_dns_ischanged = True
            else:
                if r[1] != self.detect_hex_list_dns[r[0]]['regex']:
                    del self.detect_hex_list_dns[id]
                    d = {}
                    d['id'] = int(r[0])
                    d['regex'] = str(r[1])
                    d['match_filed'] = r[2]
                    self.detect_hex_list_dns[id] = d
                    self.detect_hex_dns_ischanged = True

        deleted_id_list = []
        for id in self.detect_hex_list_dns:
            if id not in exist_id_list:
                deleted_id_list.append(id)
                self.detect_hex_dns_ischanged = True

        for id in deleted_id_list:
            del self.detect_hex_list_dns[id]

    def reset_detect_rule_status(self):
        self.detect_text_all_ischanged = False
        self.detect_hex_all_ischanged = False
        self.detect_text_dns_ischanged = False
        self.detect_hex_dns_ischanged = False

    def pull_db_all_user_debug(self, item):
        if item["id"] == 1:
            logging.debug(item)
        elif item["id"] < 0:
            logging.debug(item)

    def rows_debug(self, rows):
        for user_id in rows:
            if user_id == 1:
                logging.debug(rows[user_id])

    def pull_db_all_user(self):
        # 数据库所有用户信息
        if self.PORT_GROUP == 0:
            try:
                switchrule = importloader.load('switchrule')
                keys = switchrule.getKeys()
            except Exception as e:
                keys = [
                    'id', 'port', 'u', 'd', 'transfer_enable', 'passwd', 'enable',
                    'method', 'protocol', 'protocol_param', 'obfs', 'obfs_param',
                    'node_speedlimit', 'forbidden_ip', 'forbidden_port', 'disconnect_ip',
                    'is_multi_user'
                ]
            mu_keys = copy(keys)
        elif self.PORT_GROUP == 1:
            switchrule = importloader.load('switchrule')
            keys, user_method_keys = switchrule.getPortGroupKeys()['user'], switchrule.getPortGroupKeys()['user_method']
            mu_keys = copy(keys)
        else:
            raise Exception("Unknown port_group type %d" % self.PORT_GROUP)

        if self.ENABLE_DNSLOG == 0:
            self.enable_dnsLog = False
        else:
            self.enable_dnsLog = True

        # conn = self.getMysqlConn()

        query_sql = "SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate`,`mu_only`,`sort`,`relay_type`,`relay_to_id` FROM ss_node where `id`='" + \
                    str(self.NODE_ID) + "' AND (`node_bandwidth`<`node_bandwidth_limit` OR `node_bandwidth_limit`=0)"
        nodeinfo = self.getMysqlCur(query_sql, fetchone=True)

        if nodeinfo is None:
            rows = []
            logging.debug('nodeinfo is None')
            return rows

        logging.debug(nodeinfo)

        self.node_speedlimit = float(nodeinfo[2])
        self.traffic_rate = float(nodeinfo[3])
        self.mu_only = int(nodeinfo[4])

        if nodeinfo[5] == 10:
            self.is_relay = True
        else:
            self.is_relay = False

        self.relay_type = int(nodeinfo[6])
        self.relay_to_id = int(nodeinfo[7])
        if self.relay_type == constants.RELAY_USER_METHOD:
            query_sql = "SELECT b.`ip` as ip,a.`port` as port,a.`method` as method,a.`passwd` as passwd,a.`protocol` as protocol,a.`protocol_param` as protocol_param,a.`obfs` as obfs,a.`obfs_param` as obfs_param" \
            + " FROM user_method a,ddns b where a.`id`=" + str(self.relay_to_id) + " AND a.ddns_id=b.id"
            relay_to_um = self.getMysqlCur(query_sql, fetchone=True)
            # logging.debug(relay_to_um)
            if relay_to_um:
                # logging.debug(relay_to_um)
                d = {}
                d['des_ip'] = str(relay_to_um[0])
                d['des_port'] = int(relay_to_um[1])
                d['des_method'] = str(relay_to_um[2])
                d['des_passwd'] = str(relay_to_um[3])
                d['des_protocol'] = str(relay_to_um[4])
                d['des_protocol_param'] = str(relay_to_um[5])
                d['des_obfs'] = str(relay_to_um[6])
                d['des_obfs_param'] = str(relay_to_um[7])
                self.common_relay_rule = d

        # 获取 is_multi_use=0 的用户
        # 面板 全部用户都是 is_multi_use=0
        if self.PORT_GROUP == 0:
            # if nodeinfo[0] == 0:
            #     node_group_sql = ""
            # else:
            #     node_group_sql = "AND `node_group`=" + str(nodeinfo[0])
            import port_range
            port_mysql_str = port_range.getPortRangeMysqlStr()
            query_sql = "SELECT a." + ',a.'.join(keys) + ",c.traffic_flow as transfer_enable,c.traffic_flow_used_up as u,c.traffic_flow_used_dl as d,c.id as productid" + \
                " FROM user a,user_product_traffic c" + \
                " WHERE a.`is_multi_user`=0 AND a.`enable`=1 AND a.`expire_in`>now()" + \
                " AND a.`id`=c.`user_id` AND c.`status`=2 AND (c.`expire_time`=-1 OR c.`expire_time`>unix_timestamp())" + \
                " AND (c.`traffic_flow`>c.`traffic_flow_used_up`+c.`traffic_flow_used_dl` OR c.`traffic_flow`=-1) AND c.`node_group`=" + str(nodeinfo[0]) + \
                port_mysql_str
            ret = self.getMysqlCur(query_sql, fetchall=True)
        elif self.PORT_GROUP == 1:
            # if nodeinfo[0] == 0:
            #     node_group_sql = ""
            # else:
            #     node_group_sql = "AND a.`node_group`=" + str(nodeinfo[0])
            import port_range
            port_mysql_str = port_range.getPortRangeMysqlStrForPortGroup()
            # logging.debug(port_mysql_str)
            query_sql = "SELECT a.`" + '`,a.`'.join(keys) + "`,b.`" + '`,b.`'.join(user_method_keys) + \
                "`,c.traffic_flow as transfer_enable,c.traffic_flow_used_up as u,c.traffic_flow_used_dl as d,c.id as productid" + \
                " FROM user a,user_method b,user_product_traffic c" + \
                " WHERE a.`is_multi_user`=0 AND a.`enable`=1 AND a.`expire_in`>now() " + \
                "AND a.`id`=b.`user_id` AND b.`node_id`='" + str(self.NODE_ID) + "' " + \
                "AND a.`id`=c.`user_id` AND c.`status`=2 AND (c.`expire_time`=-1 OR c.`expire_time`>unix_timestamp()) AND (c.`traffic_flow`>c.`traffic_flow_used_up`+c.`traffic_flow_used_dl` OR c.`traffic_flow`=-1) AND c.`node_group`=" + str(nodeinfo[0]) + \
                port_mysql_str
            ret = self.getMysqlCur(query_sql, fetchall=True)
            keys += user_method_keys
        # 按顺序来
        keys += ['transfer_enable', 'u', 'd', 'productid']
        rows = []
        for r in ret:
            d = {}
            for column in range(len(keys)):
                d[keys[column]] = r[column]

            # debug
            # if d['id'] != 1:
            #     continue
            # self.pull_db_all_user_debug(d)

            rows.append(d)
        # cur.close()
        # cur = conn.cursor()
        # logging.debug(len(rows))
        # print(rows)
        # print('keys', keys)
        # print('mu_keys', mu_keys)
        # print('user_method_keys', user_method_keys)
        # mu用户，选择usermethod，不选择porduct
        # 同样受portrange影响？
        # productid 设为 -1

        # 获取 mu_port 的用户
        # if get_config().PORT_GROUP == 0:
        #     pass
        # elif get_config().PORT_GROUP == 1:
        # print('获取 mu_port')
        mu_port_keys = ['port', 'passwd', 'method', 'protocol', 'protocol_param', 'obfs', 'obfs_param']
        query_sql = "SELECT b.`" + '`,b.`'.join(mu_port_keys) + "`,a.`port_diff`,a.`type`" + \
                        " FROM mu_node a,mu_port b" + \
                        " WHERE a.`node_id`='" + str(self.NODE_ID) + "' AND a.`mu_port_id`=b.`id` AND a.`enable`=1 AND b.`enable`=1"
        # logging.debug(execute_str)
        ret = self.getMysqlCur(query_sql, fetchall=True)
        # cur.execute(execute_str)
        temp = 0
        mu_port_keys += ['port_diff', 'type']
        for r in ret:
            # print(r)
            temp_d = {}
            # d = {}
            for column in range(len(mu_port_keys)):
                temp_d[mu_port_keys[column]] = r[column]
            # print(temp_d)
            d = temp_d.copy()
            d['port'] = temp_d['port'] + temp_d['port_diff']
            d['productid'] = -1
            d['id'] = temp - 1
            d['enable_dnsLog'] = 0
            d['forbidden_port'] = ''
            d['is_multi_user'] = temp_d['type']
            d['disconnect_ip'] = None
            d['forbidden_ip'] = ''
            # logging.debug(d)
            # self.pull_db_all_user_debug(d)
            rows.append(d)
            # execute_str = "SELECT a.`" + '`,a.`'.join(mu_keys) + "`,b.`" + '`,b.`'.join(user_method_keys) + \
            #         "` FROM user a,user_method b" + \
            #         " WHERE a.`enable`=1 AND a.`expire_in`>now() AND b.`node_id`='" + str(get_config().NODE_ID) + "' " + \
            #         "AND a.`id`=b.`user_id` AND a.`is_multi_user`<>0 " +  \
            #         port_mysql_str
            # mu_keys += user_method_keys
            # print(execute_str)
            # cur.execute(execute_str)
            # for r in cur.fetchall():
            #     d = {}
            #     for column in range(len(mu_keys)):
            #         d[mu_keys[column]] = r[column]
            #     d['productid'] = -1
            #     print('d',d)
            #     rows.append(d)
        # cur.close()
        # print(rows)

        # 读取节点IP
        # SELECT * FROM `ss_node`  where `node_ip` != ''
        self.node_ip_list = []
        # cur = conn.cursor()
        ret = self.getMysqlCur(query_sql, fetchall=True)
        # cur.execute("SELECT `node_ip` FROM `ss_node`  where `node_ip` != ''")
        for r in ret:
            temp_list = str(r[0]).split(',')
            self.node_ip_list.append(temp_list[0])
        # cur.close()

        self.set_detect_rule_list()

        # 读取中转规则，如果是中转节点的话

        if self.is_relay and self.relay_type != constants.RELAY_USER_METHOD:
            # 为什么必须close才能继续execute？
            # 否则cymysql报错socket not found
            # conn = self.getMysqlConn()
            self.relay_rule_list = {}

            keys_relay = ['id', 'user_id', 'des_ip']
            keys_user_method = ['port', 'method', 'passwd', 'protocol', 'protocol_param', 'obfs', \
                'obfs_param']

            # cur = conn.cursor()
            query_sql = "SELECT a.`" \
                        + '`,a.`'.join(keys_relay) + "`, c.`port`, b.`" \
                        + '`,b.`'.join(keys_user_method) \
                        + "` FROM relay a,user_method b,user_method c WHERE a.`src_node_id` = " + str(self.NODE_ID) \
                        + " AND a.`des_user_method_id` = b.`id` AND a.`src_user_method_id` = c.`id` AND a.`is_user_method_same` = 0 AND a.`enable` = 1"
            # logging.debug(query_sql)
            # cur.execute(execute_str)
            ret = self.getMysqlCur(query_sql, fetchall=True)
            for r in ret:
                d = {}
                d['id'] = int(r[0])
                d['user_id'] = int(r[1])
                d['des_ip'] = str(r[2])
                d['src_port'] = int(r[3])
                d['des_port'] = int(r[4])
                d['des_method'] = str(r[5])
                d['des_passwd'] = str(r[6])
                d['des_protocol'] = str(r[7])
                d['des_protocol_param'] = str(r[8])
                d['des_obfs'] = str(r[9])
                d['des_obfs_param'] = str(r[10])
                self.relay_rule_list[d['id']] = d

            # cur.close()

        return rows

    def cmp(self, val1, val2):
        if isinstance(val1, bytes):
            val1 = common.to_str(val1)
        if isinstance(val2, bytes):
            val2 = common.to_str(val2)
        return val1 == val2

    def del_server_out_of_bound_safe(self, last_rows, rows):
        # 停止超流量的服务
        # 启动没超流量的服务
        # 需要动态载入switchrule，以便实时修改规则

        try:
            switchrule = importloader.load('switchrule')
        except Exception as e:
            logging.error('load switchrule.py fail')

        cur_servers = {}
        new_servers = {}

        md5_users = {}

        self.mu_port_list = []

        # 单端口多用户
        for row in rows:
            if row['is_multi_user'] != constants.is_multi_user_NOT_MULTI:
                self.mu_port_list.append(int(row['port']))
                continue

            md5_users[row['id']] = row.copy()
            del md5_users[row['id']]['u']
            del md5_users[row['id']]['d']

            if md5_users[row['id']]['disconnect_ip']  is None:
                md5_users[row['id']]['disconnect_ip'] = ''
            if md5_users[row['id']]['forbidden_ip']  is None:
                md5_users[row['id']]['forbidden_ip'] = ''
            if md5_users[row['id']]['forbidden_port']  is None:
                md5_users[row['id']]['forbidden_port'] = ''

            # if row['id'] == 1:
            #     # print(row['id'])
            #     print(md5_users[row['id']])

            # multi_user param is generated but not provided by database
            # and the param will influence the data auth, don't know the reason yet
            if len(md5_users[row['id']]['obfs_param']) > 0:
                md5_users[row['id']]['obfs_param'] = ""
            if len(md5_users[row['id']]['protocol_param']) > 0:
                md5_users[row['id']]['protocol_param'] = ""

            md5_users[row['id']]['token'] = row['passwd']
            md5_users[row['id']]['md5'] = common.get_md5(str(row['id']) + row['passwd'] + row['method'] + row['obfs'] + row['protocol'])

        # logging.debug(self.mu_port_list)
        # logging.debug(md5_users)
        # self.rows_debug(md5_users)

        for row in rows:
            self.port_uid_table[row['port']]    = row['id']
            self.uid_port_table[row['id']]      = row['port']
            self.uid_productid_table[row['id']] = row['productid']

        if self.mu_only == 1:
            i = 0
            while i < len(rows):
                if rows[i]['is_multi_user'] == constants.is_multi_user_NOT_MULTI:
                    rows.pop(i)
                    i -= 1
                else:
                    pass
                i += 1

        # self.rows_debug(rows)
        # print(len(rows),len(cur_servers))
        # for row in rows:
        #     if row['port']==36670:
        #         print(row)
        # print(rows)
        for row in rows:
            port = row['port']
            user_id = row['id']
            passwd = common.to_bytes(row['passwd'])
            cfg = {'password': passwd}
            cfg['user_id'] = user_id

            read_config_keys = [
                'method',
                'obfs',
                'obfs_param',
                'protocol',
                'protocol_param',
                'forbidden_ip',
                'forbidden_port',
                'node_speedlimit',
                'disconnect_ip',
                'is_multi_user',
                'enable_dnsLog'
            ]

            for name in read_config_keys:
                if name in row and row[name]:
                    cfg[name] = row[name]

            if 'enable_dnsLog' not in cfg:
                cfg['enable_dnsLog'] = self.enable_dnsLog
            else:
                if cfg['enable_dnsLog'] == 1:
                    cfg['enable_dnsLog'] = True
                else:
                    cfg['enable_dnsLog'] = False

            merge_config_keys = ['password'] + read_config_keys
            for name in cfg.keys():
                if hasattr(cfg[name], 'encode'):
                    try:
                        cfg[name] = cfg[name].encode('utf-8')
                    except Exception as e:
                        logging.warning( 'encode cfg key "%s" fail, val "%s"' % (name, cfg[name]))

            # logging.debug("self.node_speedlimit = %f" % self.node_speedlimit)
            if 'node_speedlimit' in cfg:
                # logging.debug("cfg['node_speedlimit'] = %f" % cfg['node_speedlimit'])
                if float(self.node_speedlimit) > 0.0 or float(cfg['node_speedlimit']) > 0.0:
                    cfg['node_speedlimit'] = max(float(self.node_speedlimit), float(cfg['node_speedlimit']))
            else:
                cfg['node_speedlimit'] = max(float(self.node_speedlimit), float(0.00))

            # logging.debug("final cfg['node_speedlimit'] = %f" % cfg['node_speedlimit'])

            if 'disconnect_ip' not in cfg:
                cfg['disconnect_ip'] = ''

            if 'forbidden_ip' not in cfg:
                cfg['forbidden_ip'] = ''

            if 'forbidden_port' not in cfg:
                cfg['forbidden_port'] = ''

            if 'protocol_param' not in cfg:
                cfg['protocol_param'] = ''

            if 'obfs_param' not in cfg:
                cfg['obfs_param'] = ''

            if 'relay_rules' not in cfg:
                cfg['relay_rules'] = {}

            if 'relay_type' not in cfg:
                cfg['relay_type'] = self.relay_type

            if 'common_relay_rule' not in cfg:
                cfg['common_relay_rule'] = {}

            if 'is_multi_user' not in cfg:
                cfg['is_multi_user'] = constants.is_multi_user_NOT_MULTI

            if port not in cur_servers:
                cur_servers[port] = passwd
            else:
                # print(len(cur_servers),cur_servers)
                logging.error(
                    'more than one user use the same port [%s] or there is an another process bind at this port' % (port,))
                continue

            if cfg['is_multi_user'] != constants.is_multi_user_NOT_MULTI:
                cfg['users_table'] = md5_users.copy()

            cfg['detect_text_list_all'] = self.detect_text_list_all.copy()
            cfg['detect_hex_list_all'] = self.detect_hex_list_all.copy()
            cfg['detect_text_list_dns'] = self.detect_text_list_dns.copy()
            cfg['detect_hex_list_dns'] = self.detect_hex_list_dns.copy()

            # logging.debug(self.relay_rule_list)
            # logging.debug(self.is_relay)
            if self.relay_type == constants.RELAY_CUSTOM:
                temp_relay_rules = {}
                for id in self.relay_rule_list:
                    if cfg['is_multi_user'] != constants.is_multi_user_NOT_MULTI:
                        # 单端口需要推送每个中转规则
                        if self.relay_rule_list[id]['src_port'] == row['port']:
                            temp_relay_rules[id] = self.relay_rule_list[id]
                        else:
                            continue
                    else:
                        if self.relay_rule_list[id]['user_id'] == user_id and self.relay_rule_list[id]['src_port'] == row['port']:
                            temp_relay_rules[id] = self.relay_rule_list[id]
                        else:
                            continue
                cfg['relay_rules'] = temp_relay_rules.copy()
            elif self.relay_type == constants.RELAY_USER_METHOD:
                cfg['relay_rules'] = {}
                cfg['common_relay_rule'] = self.common_relay_rule
                # logging.debug(self.common_relay_rule)
            elif self.relay_type == constants.RELAY_NO:
                temp_relay_rules = {}
                cfg['relay_rules'] = temp_relay_rules.copy()

            if ServerPool.get_instance().server_is_run(port) > 0:
                # server is running
                # xun-huan zai-ru gui-ze, you xin-gui-ze shi, ze hui tong-guo xun-huan de-dao geng-xin
                cfgchange = False
                if self.detect_text_all_ischanged or self.detect_hex_all_ischanged:
                    logging.info('[if self.detect_text_all_ischanged or self.detect_hex_all_ischanged] cfgchange = True')
                    cfgchange = True
                if self.detect_text_dns_ischanged or self.detect_hex_dns_ischanged:
                    logging.info('[if self.detect_text_dns_ischanged or self.detect_hex_dns_ischanged] cfgchange = True')
                    if not cfgchange:
                        cfgchange = True

                if port in ServerPool.get_instance().tcp_servers_pool:
                    ServerPool.get_instance().tcp_servers_pool[port].modify_detect_text_list_all(self.detect_text_list_all)
                    ServerPool.get_instance().tcp_servers_pool[port].modify_detect_hex_list_all(self.detect_hex_list_all)
                if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                    ServerPool.get_instance().tcp_ipv6_servers_pool[port].modify_detect_text_list_all(self.detect_text_list_all)
                    ServerPool.get_instance().tcp_ipv6_servers_pool[port].modify_detect_hex_list_all(self.detect_hex_list_all)

                if port in ServerPool.get_instance().tcp_servers_pool:
                    ServerPool.get_instance().tcp_servers_pool[port].modify_detect_text_list_dns(self.detect_text_list_dns)
                    ServerPool.get_instance().tcp_servers_pool[port].modify_detect_hex_list_dns(self.detect_hex_list_dns)
                if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                    ServerPool.get_instance().tcp_ipv6_servers_pool[port].modify_detect_text_list_dns(self.detect_text_list_dns)
                    ServerPool.get_instance().tcp_ipv6_servers_pool[port].modify_detect_hex_list_dns(self.detect_hex_list_dns)

                # udp have no dns part
                if port in ServerPool.get_instance().udp_servers_pool:
                    ServerPool.get_instance().udp_servers_pool[port].modify_detect_text_list(self.detect_text_list_all)
                    ServerPool.get_instance().udp_servers_pool[port].modify_detect_hex_list(self.detect_hex_list_all)
                if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                    ServerPool.get_instance().udp_ipv6_servers_pool[port].modify_detect_text_list(self.detect_text_list_all)
                    ServerPool.get_instance().udp_ipv6_servers_pool[port].modify_detect_hex_list(self.detect_hex_list_all)

                if row['is_multi_user'] != constants.is_multi_user_NOT_MULTI:
                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[port].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[port].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[port].modify_multi_user_table(md5_users)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[port].modify_multi_user_table(md5_users)

                if self.relay_type == constants.RELAY_CUSTOM:
                    temp_relay_rules = {}
                    for id in self.relay_rule_list:
                        if cfg['is_multi_user'] != constants.is_multi_user_NOT_MULTI:
                            if self.relay_rule_list[id]['src_port'] == row['port']:
                                temp_relay_rules[id] = self.relay_rule_list[id]
                            else:
                                continue
                        else:
                            if self.relay_rule_list[id]['user_id'] == user_id and self.relay_rule_list[id]['src_port'] == row['port']:
                                temp_relay_rules[id] = self.relay_rule_list[id]
                            else:
                                continue

                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[port].push_relay_rules(temp_relay_rules)
                elif self.relay_type == constants.RELAY_USER_METHOD:
                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[port].push_common_relay_rule(self.common_relay_rule)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[port].push_common_relay_rule(self.common_relay_rule)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[port].push_common_relay_rule(self.common_relay_rule)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[port].push_common_relay_rule(self.common_relay_rule)
                elif self.relay_type == constants.RELAY_NO:
                    temp_relay_rules = {}

                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[port].push_relay_rules(temp_relay_rules)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[port].push_relay_rules(temp_relay_rules)

                if port in ServerPool.get_instance().tcp_servers_pool:
                    relay = ServerPool.get_instance().tcp_servers_pool[port]
                    for name in merge_config_keys:
                        if name in cfg and not self.cmp(cfg[name], relay._config[name]):
                            cfgchange = True
                            break
                if not cfgchange and port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                    relay = ServerPool.get_instance().tcp_ipv6_servers_pool[port]
                    for name in merge_config_keys:
                        if name in cfg and not self.cmp(cfg[name], relay._config[name]):
                            cfgchange = True
                            break
                # if config changed, then restart this server
                if cfgchange:
                    self.del_server(port, "config changed")
                    new_servers[port] = (passwd, cfg)
            elif ServerPool.get_instance().server_run_status(port) is False:
                # server is not running
                # new_servers[port] = passwd
                self.new_server(port, passwd, cfg)

        # print(len(rows),len(cur_servers))

        for row in last_rows:
            if row['port'] in cur_servers:
                pass
            else:
                self.del_server(row['port'], "port not exist")

        if len(new_servers) > 0:
            from shadowsocks import eventloop
            self.event.wait(eventloop.TIMEOUT_PRECISION + eventloop.TIMEOUT_PRECISION / 2)
            for port in new_servers.keys():
                passwd, cfg = new_servers[port]
                self.new_server(port, passwd, cfg)

        ServerPool.get_instance().push_uid_port_table(self.uid_port_table)

    def del_server(self, port, reason):
        logging.info('db stop server at port [%s] reason: %s!' % (port, reason))
        ServerPool.get_instance().cb_del_server(port)
        if port in self.last_update_transfer:
            del self.last_update_transfer[port]

        for mu_user_port in self.mu_port_list:
            if mu_user_port in ServerPool.get_instance().tcp_servers_pool:
                ServerPool.get_instance().tcp_servers_pool[mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                ServerPool.get_instance().tcp_ipv6_servers_pool[mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().udp_servers_pool:
                ServerPool.get_instance().udp_servers_pool[mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])
            if mu_user_port in ServerPool.get_instance().udp_ipv6_servers_pool:
                ServerPool.get_instance().udp_ipv6_servers_pool[mu_user_port].reset_single_multi_user_traffic(self.port_uid_table[port])

    def new_server(self, port, passwd, cfg):
        protocol = cfg.get(
            'protocol',
            ServerPool.get_instance().config.get(
                'protocol',
                'origin'))
        method = cfg.get('method', ServerPool.get_instance().config.get('method', 'None'))
        obfs = cfg.get('obfs', ServerPool.get_instance().config.get('obfs', 'plain'))
        logging.info(
            'db start server at port [%s] pass [%s] protocol [%s] method [%s] obfs [%s]' %
            (port, passwd, protocol, method, obfs))
        ServerPool.get_instance().new_server(port, cfg)

    @staticmethod
    def del_servers():
        global db_instance
        for port in [
                v for v in ServerPool.get_instance().tcp_servers_pool.keys()]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)
                if port in db_instance.last_update_transfer:
                    del db_instance.last_update_transfer[port]
        for port in [
                v for v in ServerPool.get_instance().tcp_ipv6_servers_pool.keys()]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)
                if port in db_instance.last_update_transfer:
                    del db_instance.last_update_transfer[port]

    @staticmethod
    def thread_db(obj):
        import socket
        import time
        global db_instance
        timeout = 60
        socket.setdefaulttimeout(timeout)
        last_rows = []
        db_instance = obj()

        shell.log_shadowsocks_version()
        try:
            import resource
            logging.info(
                'current process RLIMIT_NOFILE resource: soft %d hard %d' %
                resource.getrlimit(
                    resource.RLIMIT_NOFILE))
        except:
            pass
        try:
            while True:
                load_config()
                try:
                    db_instance.push_db_all_user()
                    rows = db_instance.pull_db_all_user()
                    db_instance.del_server_out_of_bound_safe(last_rows, rows)
                    db_instance.reset_detect_rule_status()
                    last_rows = rows
                    db_instance.closeMysqlConn()
                    # logging.info('try end')
                except Exception as e:
                    trace = traceback.format_exc()
                    logging.error(trace)
                    # logging.warn('db thread except:%s' % e)
                # logging.info('except end')
                # waiting for stop signal
                # stop => signal is True
                # continue => signal is False
                if db_instance.event.wait(60) or not db_instance.is_all_thread_alive():
                    break
                # logging.info('if db_instance.has_stopped:')
                if db_instance.has_stopped:
                    break
        except KeyboardInterrupt as e:
            pass
        db_instance.del_servers()
        ServerPool.get_instance().stop()
        db_instance = None

    @staticmethod
    def thread_db_stop():
        global db_instance
        db_instance.has_stopped = True
        db_instance.event.set()

    def is_all_thread_alive(self):
        if not ServerPool.get_instance().thread.is_alive():
            return False
        return True

