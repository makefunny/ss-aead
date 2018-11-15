#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import socket
from server_pool import ServerPool
import traceback
from shadowsocks import common, shell, lru_cache
from configloader import load_config, get_config
import importloader
import platform
import datetime
import fcntl


def getMysqlConn():
    if get_config().MYSQL_SSL_ENABLE == 1:
        conn = cymysql.connect(
            host=get_config().MYSQL_HOST,
            port=get_config().MYSQL_PORT,
            user=get_config().MYSQL_USER,
            passwd=get_config().MYSQL_PASS,
            db=get_config().MYSQL_DB,
            charset='utf8',
            ssl={
                'ca': get_config().MYSQL_SSL_CA,
                'cert': get_config().MYSQL_SSL_CERT,
                'key': get_config().MYSQL_SSL_KEY})
    else:
        conn = cymysql.connect(
            host=get_config().MYSQL_HOST,
            port=get_config().MYSQL_PORT,
            user=get_config().MYSQL_USER,
            passwd=get_config().MYSQL_PASS,
            db=get_config().MYSQL_DB,
            charset='utf8')

    conn.autocommit(True)
    return conn

def getPortRangeMysqlStr():
    if len(get_config().PORT_NOT_ALLOW_LIST)>0:
        l = get_config().PORT_NOT_ALLOW_LIST
        port_not_allow_mysql_str = ""
        for i in l:
            port_not_allow_mysql_str += " AND `a.port`!="
            port_not_allow_mysql_str += str(i)
    else:
        port_not_allow_mysql_str = ""

    if len(get_config().PORT_ALLOW_RANGE)==2:
        l = get_config().PORT_ALLOW_RANGE
        port_allow_range_mysql_str = ""
        port_allow_range_mysql_str += " AND `a.port`>="
        port_allow_range_mysql_str += str(l[0])
        port_allow_range_mysql_str += " AND `a.port`<="
        port_allow_range_mysql_str += str(l[1])
    else:
        port_allow_range_mysql_str = ""

    if len(get_config().PORT_NOT_ALLOW_RANGE)==2:
        l = get_config().PORT_NOT_ALLOW_RANGE
        port_not_allow_range_mysql_str = ""
        port_not_allow_range_mysql_str += " AND (`a.port`<"
        port_not_allow_range_mysql_str += str(l[0])
        port_not_allow_range_mysql_str += " OR `a.port`>"
        port_not_allow_range_mysql_str += str(l[1])
        port_not_allow_range_mysql_str += ")"
    else:
        port_not_allow_range_mysql_str = ""

    port_mysql_str = port_allow_range_mysql_str + port_not_allow_mysql_str
    port_mysql_str += port_not_allow_range_mysql_str
    return port_mysql_str

def getPortRangeMysqlStrForPortGroup():
    if len(get_config().PORT_NOT_ALLOW_LIST)>0:
        l = get_config().PORT_NOT_ALLOW_LIST
        port_not_allow_mysql_str = ""
        for i in l:
            port_not_allow_mysql_str += " AND b.`port`!="
            port_not_allow_mysql_str += str(i)
    else:
        port_not_allow_mysql_str = ""

    if len(get_config().PORT_ALLOW_RANGE)==2:
        l = get_config().PORT_ALLOW_RANGE
        port_allow_range_mysql_str = ""
        port_allow_range_mysql_str += " AND b.`port`>="
        port_allow_range_mysql_str += str(l[0])
        port_allow_range_mysql_str += " AND b.`port`<="
        port_allow_range_mysql_str += str(l[1])
    else:
        port_allow_range_mysql_str = ""

    if len(get_config().PORT_NOT_ALLOW_RANGE)==2:
        l = get_config().PORT_NOT_ALLOW_RANGE
        port_not_allow_range_mysql_str = ""
        port_not_allow_range_mysql_str += " AND (b.`port`<"
        port_not_allow_range_mysql_str += str(l[0])
        port_not_allow_range_mysql_str += " OR b.`port`>"
        port_not_allow_range_mysql_str += str(l[1])
        port_not_allow_range_mysql_str += ")"
    else:
        port_not_allow_range_mysql_str = ""

    port_mysql_str = port_allow_range_mysql_str + port_not_allow_mysql_str
    port_mysql_str += port_not_allow_range_mysql_str
    return port_mysql_str

def getMysqlUsers():
    switchrule = importloader.load('switchrule')
    keys = switchrule.getKeys()
    conn = getMysqlConn()
    cur = conn.cursor()
    cur.execute("SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate`,`mu_only`,`sort` FROM ss_node where `id`='" +
                str(get_config().NODE_ID) + "' AND (`node_bandwidth`<`node_bandwidth_limit` OR `node_bandwidth_limit`=0)")
    nodeinfo = cur.fetchone()

    if nodeinfo is None:
        rows = []
        cur.close()
        conn.commit()
        conn.close()
        return rows

    if nodeinfo[0] == 0:
        node_group_sql = ""
    else:
        node_group_sql = "AND `node_group`=" + str(nodeinfo[0])

    port_mysql_str = getPortRangeMysqlStr()

    cur.close()
    cur = conn.cursor()
    cur.execute("SELECT " + ','.join(keys) +
                    " FROM user WHERE ((`class`>=" + str(nodeinfo[1]) + " " + node_group_sql + ") OR `is_admin`=1) \
                    AND`enable`=1 AND `expire_in`>now() AND `transfer_enable`>`u`+`d`" + port_mysql_str)
    rows = []
    for r in cur.fetchall():
        d = {}
        for column in range(len(keys)):
            d[keys[column]] = r[column]
        rows.append(d)
    cur.close()

    for r in rows:
        print(r['port'])

def getWebUsersDelBanPort():
    import webapi_utils
    webapi = webapi_utils.WebApi()
    data = webapi.getApi('users', {'node_id': get_config().NODE_ID})
    indexTodel = []
    i=0
    for item in data:
        DEL = False
        if len(get_config().PORT_NOT_ALLOW_LIST)>0:
            for list_not_allow in get_config().PORT_NOT_ALLOW_LIST:
                if item['port'] == list_not_allow:
                    indexTodel.append(i)
                    DEL = True
                    i = i+1
                    break
        if DEL:
            continue
        if len(get_config().PORT_ALLOW_RANGE)==2:
            if item['port'] < get_config().PORT_ALLOW_RANGE[0] or item['port'] > get_config().PORT_ALLOW_RANGE[1]:
                indexTodel.append(i)
                DEL = True
                i = i+1
        if DEL:
            continue
        if len(get_config().PORT_NOT_ALLOW_RANGE)==2:
            if item['port'] >= get_config().PORT_NOT_ALLOW_RANGE[0] and item['port'] <= get_config().PORT_NOT_ALLOW_RANGE[1]:
                indexTodel.append(i)
                DEL = True
                i = i+1
        if DEL:
            continue
        i = i+1
    print( "i: ", i )
    if len(indexTodel)>0:
        for l in indexTodel:
            print("[DELETE PORT]", data.pop(l)['port'])
    return data

if __name__ == '__main__':
    if get_config().API_INTERFACE == 'modwebapi':
        getWebUsersDelBanPort()
    else:
        import cymysql
        getMysqlUsers()
