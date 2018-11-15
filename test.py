import time
import sys
import threading
import os

import server_pool

from configloader import load_config, get_config

import db_transfer
import web_transfer

class TestConnect():

    def __init__(self):
        self.mysql_conn = None

    def checkConnect(self):
        if get_config().API_INTERFACE == 'modwebapi':
            self.checkWebApi()
        else:
            # self.checkMysql()
            self.checkMysql_newVer()

    def setMysqlConn(self, db_base=None):
        import cymysql

        if db_base is None:
            db_base=get_config().MYSQL_DB

        if get_config().MYSQL_SSL_ENABLE == 1:
            conn = cymysql.connect(
                    host=get_config().MYSQL_HOST,
                    port=get_config().MYSQL_PORT,
                    user=get_config().MYSQL_USER,
                    passwd=get_config().MYSQL_PASS,
                    db=db_base,
                    charset='utf8',
                    ssl={
                        'ca': get_config().MYSQL_SSL_CA,
                        'cert': get_config().MYSQL_SSL_CERT,
                        'key': get_config().MYSQL_SSL_KEY
                    }
                )
        else:
            conn = cymysql.connect(
                    host=get_config().MYSQL_HOST,
                    port=get_config().MYSQL_PORT,
                    user=get_config().MYSQL_USER,
                    passwd=get_config().MYSQL_PASS,
                    db=db_base,
                    charset='utf8'
                )
        conn.autocommit(True)
        self.mysql_conn = conn

    def checkWebApi(self):
        import webapi_utils
        webapi = webapi_utils.WebApi()

        try:
            nodeinfo = webapi.getApi( 'nodes/%d/info' % (get_config().NODE_ID) )
            print('Nodeinfo', nodeinfo)
        except Exception as e:
            print('[Failed]', e)

        try:
            user_data = webapi.getApi('users', {'node_id': get_config().NODE_ID})
            print('Userinfo', user_data[0])
        except Exception as e:
            print('[Failed]', e)

    def checkMysqlPort(self):
        import socket
        host=get_config().MYSQL_HOST
        port=get_config().MYSQL_PORT
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t_start = round(time.time()*1000)
        try:
            s.settimeout(1)
            s.connect( (host,port) )
            s.shutdown(socket.SHUT_RD)
            t_end = round(time.time()*1000)
            s.settimeout(None)
            print('[success] mysql port connect successfully! Server: ', host, ' Port: ', port, ' Time: ', t_end-t_start, 'ms')
            # return (t_end-t_start)
            # return 0
        except Exception as e:
            s.settimeout(None)
            print('[failed] mysql port connect failed! Server: ', host, ' Port: ', port)
            # return 1
        print()

    def checkMysql(self):
        self.checkMysqlPort()

        self.setMysqlConn('mysql')
        cur = self.mysql_conn.cursor()
        try:
            cur.execute("SELECT `user`,`host` FROM `user`")
            re = cur.fetchall()
            print(re)
        except Exception as e:
            print('[Failed]', e)
        cur.close()

        self.setMysqlConn()
        cur = self.mysql_conn.cursor()

        try:
            cur.execute("SELECT `id`,`email`,`port` FROM `user` limit 5")
            re = cur.fetchall()
            print('[Userinfo]', re)
        except Exception as e:
            print('[Failed]', e)

        try:
            cur.execute("SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate`,`mu_only`,`sort` FROM ss_node where `id`='" + str(get_config().NODE_ID) + "'")
            re = cur.fetchall()
            print('[Nodeinfo]', re)
        except Exception as e:
            print('[Failed]', e)

        try:
            cur.execute("SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate`,`mu_only`,`sort` FROM ss_node where `id`='" + str(get_config().NODE_ID) + "' AND (`node_bandwidth`<`node_bandwidth_limit` OR `node_bandwidth_limit`=0)")
            re = cur.fetchall()
            print('[Nodeinfo]', re)
        except Exception as e:
            print('[Failed]', e)

        cur.close()

        print()
        self.mysql_conn.close()

    def checkMysql_newVer(self):
        self.checkMysqlPort()

        self.setMysqlConn('ccavsorg')
        cur = self.mysql_conn.cursor()

        try:
            cur.execute("SELECT * FROM `user_product_traffic` WHERE `expire_time`>unix_timestamp()")
            re = cur.fetchall()
            print(len(re))
        except Exception as e:
            print('[Failed]', e)


        cur.close()
        print()
        self.mysql_conn.close()


if __name__ == '__main__':
    os.system('clear')
    print()
    a = TestConnect()
    a.checkConnect()