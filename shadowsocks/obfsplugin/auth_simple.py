#!/usr/bin/env python
#
# Copyright 2015-2015 breakwa11
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging
import struct

from shadowsocks.common import ord

def create_auth_simple(method):
    return auth_simple(method)

obfs_map = {
        'auth_simple': (create_auth_simple,),
}

class auth_simple(object):
    def __init__(self, method):
        self.method = method
        self.server_info = None
        self.has_sent_header = False
        self.has_recv_header = False

    def init_data(self):
        return b''

    def get_overhead(self, direction): # direction: true for c->s false for s->c
        return 0

    def get_server_info(self):
        return self.server_info

    def set_server_info(self, server_info):
        self.server_info = server_info

    # token => less than 255
    # buf   => less than 65535
    # struct.pack(">H", len(buf)) => length == 2
    def client_pre_encrypt(self, buf):
        token=b'exampletoken'
        # logging.info('client_pre_encrypt >> %d %s' % (len(buf),buf))
        result = bytes([len(token)])+token + struct.pack(">H", len(buf))+buf
        # logging.info('client_pre_encrypted >> %d %s' % (len(result),result))
        return result

    def client_encode(self, buf):
        # logging.info('client_encode >> %s' % buf)
        return buf

    def client_decode(self, buf):
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def client_post_decrypt(self, buf):
        # logging.info('client_post_decrypt >> %s' % buf)
        return buf

    # 服务器 => 客户端
    def server_pre_encrypt(self, buf):
        # 此处对raw data进行预处理，之后根据加密方式进行加密
        # logging.info('server_pre_encrypt >> tcp-buf %s' % buf)
        return buf
        # token=b'exampletoken'
        # logging.info('client_pre_encrypt >> %d %s' % (len(buf),buf))
        # result = bytes([len(token)])+token + struct.pack(">H", len(buf))+buf
        # logging.info('client_pre_encrypted >> %d %s' % (len(result),result))
        # return result

    def server_encode(self, buf):
        # logging.info('server_encode >> tcp-buf %s' % buf)
        return buf

    def server_decode(self, buf):
        # logging.info('server_decode >> tcp-buf %s' % buf)
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (buf, True, False)

    # 解密 客户端 => 服务端
    def server_post_decrypt(self, buf):
        # print('对解密结果进行二次处理 >> tcp-buf ' , buf)
        # logging.info('server_post_decrypt >> tcp-buf %s' % buf)

        is_Body = False
        body = b''
        token = b''

        TOKEN_LENGTH_LENGTH=1
        BODY_LENGTH_LENGTH=2
        LENGTH_LENGTH=0
        # len(buf)-1 => 最后一位可读index

        length_index = 0
        while length_index < len(buf)-1:
            if is_Body==False:
                LENGTH_LENGTH=TOKEN_LENGTH_LENGTH
                length = ord(buf[length_index])
                if token==b'':
                    token = buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]
                elif token!=buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]:
                    raise Exception('Token dismatch')
                is_Body=True

                if length_index+LENGTH_LENGTH+length == len(buf):
                    # end
                    break
                elif length_index+LENGTH_LENGTH+length == len(buf)-BODY_LENGTH_LENGTH:
                    raise Exception('Token not found')
                    break

            else:
                LENGTH_LENGTH=BODY_LENGTH_LENGTH
                length  =  struct.unpack(">H", buf[length_index:length_index+LENGTH_LENGTH])[0]
                body    += buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]
                is_Body =  False

                if length_index+LENGTH_LENGTH+length == len(buf):
                    # end
                    break
                elif length_index+LENGTH_LENGTH+length == len(buf)-TOKEN_LENGTH_LENGTH:
                    raise Exception('Body not found')
                    break

            length_index=length_index+LENGTH_LENGTH+length


        return (body, False, token)

        token_len = ord(buf[0])
        index = head_len+1
        token = buf[1:token_len+1]

        if token_len+1 == len(buf):
            return (b'', False, token)
        elif token_len+1 == len(buf)-1:
            raise Exception('Error body_len')



        head_len = ord(buf[0])

        # buf[0] => head_len
        # buf[1:head_len+1] => head
        # buf[head_len+1] => token_len
        # buf[head_len+2:head_len+2+ord(buf[head_len+1])] => token
        # buf[head_len+2+ord(buf[head_len+1]):] => req body

        if head_len+1 == len(buf):
            return 

        return (buf[1:head_len+1] + buf[head_len+2+ord(buf[head_len+1]):], False, buf[head_len+2:head_len+2+ord(buf[head_len+1])])


        # if not self.has_recv_header:
        #     logging.info('self.has_recv_header == True')
        #     # print('self.has_sent_header == false')
        #     self.has_recv_header = True
        #     return (buf, False)
        # else:
        #     return (buf[1:], False)

    # def client_udp_pre_encrypt(self, buf, token):
    def client_udp_pre_encrypt(self,buf):
        token=b'exampletoken'
        # header 跟body一起，不确定位置，token放后面
        # logging.info('client_udp_pre_encrypt >> udp-buf %s' % buf)
        return buf + token+bytes([len(token)])
        # return buf

    def client_udp_post_decrypt(self, buf):
        return buf

    # 服务器 => 客户端
    def server_udp_pre_encrypt(self, buf, uid):
        # token=b'exampletoken'
        # logging.info('server_udp_pre_encrypt >> udp-buf %s' % buf)
        # return buf + token+bytes([len(token)])
        return buf

    # 解密 客户端 => 服务端
    def server_udp_post_decrypt(self, buf):
        # logging.info('udp-buf %s' % buf)
        token_len = ord(buf[-1])
        # print(token_len,buf[:len(buf)-token_len-1], buf[-token_len-1:-1])
        return (buf[:len(buf)-token_len-1], buf[-token_len-1:-1])
        # return (buf, None)

    def dispose(self):
        pass

    def get_head_size(self, buf, def_value):
        if len(buf) < 2:
            return def_value
        head_type = ord(buf[0]) & 0x7
        if head_type == 1:
            return 7
        if head_type == 4:
            return 19
        if head_type == 3:
            return 4 + ord(buf[1])
        return def_value
