# import time
# import sys
# import threading
# import os

# import server_pool
# from configloader import load_config, get_config

# import db_transfer
# import web_transfer

import timeit

# class TestConnect():

#     def __init__(self):
#         self.mysql_conn = None

#     def checkConnect(self):
#         if get_config().API_INTERFACE == 'modwebapi':
#             self.checkWebApi()
#         else:
#             # self.checkMysql()
#             self.checkMysql_newVer()

#     def setMysqlConn(self, db_base=None):
#         import cymysql

#         if db_base is None:
#             db_base=get_config().MYSQL_DB

#         if get_config().MYSQL_SSL_ENABLE == 1:
#             conn = cymysql.connect(
#                     host=get_config().MYSQL_HOST,
#                     port=get_config().MYSQL_PORT,
#                     user=get_config().MYSQL_USER,
#                     passwd=get_config().MYSQL_PASS,
#                     db=db_base,
#                     charset='utf8',
#                     ssl={
#                         'ca': get_config().MYSQL_SSL_CA,
#                         'cert': get_config().MYSQL_SSL_CERT,
#                         'key': get_config().MYSQL_SSL_KEY
#                     }
#                 )
#         else:
#             conn = cymysql.connect(
#                     host=get_config().MYSQL_HOST,
#                     port=get_config().MYSQL_PORT,
#                     user=get_config().MYSQL_USER,
#                     passwd=get_config().MYSQL_PASS,
#                     db=db_base,
#                     charset='utf8'
#                 )
#         conn.autocommit(True)
#         self.mysql_conn = conn

#     def checkWebApi(self):
#         import webapi_utils
#         webapi = webapi_utils.WebApi()

#         try:
#             nodeinfo = webapi.getApi( 'nodes/%d/info' % (get_config().NODE_ID) )
#             print('Nodeinfo', nodeinfo)
#         except Exception as e:
#             print('[Failed]', e)

#         try:
#             user_data = webapi.getApi('users', {'node_id': get_config().NODE_ID})
#             print('Userinfo', user_data[0])
#         except Exception as e:
#             print('[Failed]', e)

#     def checkMysqlPort(self):
#         import socket
#         host=get_config().MYSQL_HOST
#         port=get_config().MYSQL_PORT
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         t_start = round(time.time()*1000)
#         try:
#             s.settimeout(1)
#             s.connect( (host,port) )
#             s.shutdown(socket.SHUT_RD)
#             t_end = round(time.time()*1000)
#             s.settimeout(None)
#             print('[success] mysql port connect successfully! Server: ', host, ' Port: ', port, ' Time: ', t_end-t_start, 'ms')
#             # return (t_end-t_start)
#             # return 0
#         except Exception as e:
#             s.settimeout(None)
#             print('[failed] mysql port connect failed! Server: ', host, ' Port: ', port)
#             # return 1
#         print()

#     def checkMysql(self):
#         self.checkMysqlPort()

#         self.setMysqlConn('mysql')
#         cur = self.mysql_conn.cursor()
#         try:
#             cur.execute("SELECT `user`,`host` FROM `user`")
#             re = cur.fetchall()
#             print(re)
#         except Exception as e:
#             print('[Failed]', e)
#         cur.close()

#         self.setMysqlConn()
#         cur = self.mysql_conn.cursor()

#         try:
#             cur.execute("SELECT `id`,`email`,`port` FROM `user` limit 5")
#             re = cur.fetchall()
#             print('[Userinfo]', re)
#         except Exception as e:
#             print('[Failed]', e)

#         try:
#             cur.execute("SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate`,`mu_only`,`sort` FROM ss_node where `id`='" + str(get_config().NODE_ID) + "'")
#             re = cur.fetchall()
#             print('[Nodeinfo]', re)
#         except Exception as e:
#             print('[Failed]', e)

#         try:
#             cur.execute("SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate`,`mu_only`,`sort` FROM ss_node where `id`='" + str(get_config().NODE_ID) + "' AND (`node_bandwidth`<`node_bandwidth_limit` OR `node_bandwidth_limit`=0)")
#             re = cur.fetchall()
#             print('[Nodeinfo]', re)
#         except Exception as e:
#             print('[Failed]', e)

#         cur.close()

#         print()
#         self.mysql_conn.close()

#     def checkMysql_newVer(self):
#         self.checkMysqlPort()

#         self.setMysqlConn('ccavsorg')
#         cur = self.mysql_conn.cursor()

#         try:
#             cur.execute("SELECT * FROM `user_product_traffic` WHERE `expire_time`>unix_timestamp()")
#             re = cur.fetchall()
#             print(len(re))
#         except Exception as e:
#             print('[Failed]', e)


#         cur.close()
#         print()
#         self.mysql_conn.close()

def match_begin(str1, str2):
    if len(str1) >= len(str2):
        if str1[:len(str2)] == str2:
            return True
    return False

def getHost_v1(buf):
    lines = buf.split(b'\r\n')
    if lines and len(lines) > 1:
        for line in lines:
            if match_begin(line, b"Host: "):
                return line[6:]
    return b""

def getHost_v2(buf):
    if b"Host: " in buf:
        if b'\r' in buf:
            return b"0"
    return b"0"

# b"H" = 72
# b"o" = 111
# b"s" = 115
# b"t" = 116
# b":" = 58
# b" " = 32



def getHost_v3(buf):
    start = buf.find(b"Host: ")
    if start == -1:
        return b""
    # b"\r" = 13
    end   = buf.find(13, start)
    if end == -1:
        return b""
    return buf[start:end]
    # toFind = b"Host: "
    # i = 0
    # while True:
    #     if buf[i] == 72:
    #         if buf[i:i+6] == b"Host: ":
    #             return b"0"
    #     if i == 40:
    #         break
    #     i+=1
    # for i in [0,1,2,3,4,5,6,7,8,9,10,11,12]:
    #     if buf[i] == 72:
    #         return b"0"
    # for s in buf:
    #     if s == 72:
    #         return b"0"
        # if s == ord(toFind[:1]):
        #     return b"0"
    return b"0"

def main():
    t   = timeit.repeat(
        setup   = "from __main__ import getHost_v1, match_begin",
        stmt    = "getHost_v1(b\"POST / HTTP/1.1\\r\\nHost: 127.0.0.1:2000\\r\\nUser-Agent: curl/7.66.0\\r\\nAccept: */*\\r\\nContent-Length: 21\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n\\r\\n4e9i8jh98sadjf9qjw39q\")",
        number  = 500000)
    print(t)
    t   = timeit.repeat(
        setup   = "from __main__ import getHost_v2",
        stmt    = "getHost_v2(b\"POST / HTTP/1.1\\r\\nHost: 127.0.0.1:2000\\r\\nUser-Agent: curl/7.66.0\\r\\nAccept: */*\\r\\nContent-Length: 21\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n\\r\\n4e9i8jh98sadjf9qjw39q\")",
        number  = 500000)
    print(t)
    t   = timeit.repeat(
        setup   = "from __main__ import getHost_v3",
        stmt    = "getHost_v3(b\"POST / HTTP/1.1\\r\\nHost: 127.0.0.1:2000\\r\\nUser-Agent: curl/7.66.0\\r\\nAccept: */*\\r\\nContent-Length: 21\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n\\r\\n4e9i8jh98sadjf9qjw39q\")",
        number  = 500000)
    print(t)

if __name__ == '__main__':
    main()
    # print(getHost_v3(b"POST / HTTP/1.1\r\nHost: 127.0.0.1:2000\r\nUser-Agent: curl/7.66.0\r\nAccept: */*\r\nContent-Length: 21\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n4e9i8jh98sadjf9qjw39q"))
    # os.system('clear')
    # print()
    # a = TestConnect()
    # a.checkConnect()