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

        self.debug_token = b'test'

        self.body_remain = 0

        self.body_length_remain = 0
        self.last_body_length   = []

        self.last_token   = b''
        self.token_remain = 0

        self.uid         = 0

    def init_data(self):
        return b''

    def get_overhead(self, direction): # direction: true for c->s false for s->c
        return 0

    def get_server_info(self):
        # print('auth_simple.py',dir(self.server_info), type(self.server_info))
        return self.server_info

    def set_server_info(self, server_info):
        # print(server_info, dir(server_info))
        self.server_info = server_info
        # print(dir(self.server_info))
        # print(self.server_info.buffer_size)
        logging.debug('self.server_info.tcp_mss >> %d', self.server_info.tcp_mss)
        logging.debug('self.server_info.buffer_size >> %d', self.server_info.buffer_size)
        logging.debug('self.server_info.decipher_iv_len >> %d', self.server_info.decipher_iv_len)

    # token => less than 255
    # buf   => less than 65535
    # struct.pack(">H", len(buf)) => length == 2
    def client_pre_encrypt(self, buf):
        token=self.debug_token
        result = bytes([len(token)]) + token + struct.pack(">H", len(buf)) + buf
        # logging.debug('client_pre_encrypted >> success >> tcp >> length:%d >> %s' % (len(result),result))
        logging.debug('client_pre_encrypted >> success >> tcp >> length:%d' % len(result))
        return result

    def client_pre_encrypt_buff(self, buf):
        token=self.debug_token
        result = b''
        token_block = bytes([len(token)]) + token

        # 2 >> body_length_length
        # split_body_len = 32752 - len(token_block) - 2
        split_body_len = self.server_info.buffer_size - self.server_info.decipher_iv_len - len(token_block) - 2

        # split_count = int(len(buf) / split_body_len)
        split_begin = 0

        while split_begin < len(buf):

            if split_begin+split_body_len >= len(buf):
                split_body_len = len(buf) - split_begin

            temp_body_block = struct.pack(">H", split_body_len) + buf[split_begin:split_begin+split_body_len]
            split_begin += split_body_len
            result += token_block + temp_body_block
            logging.debug('client_pre_encrypted >  body >> tcp >> length:%d:%s total_length:%d' % (split_body_len, struct.pack(">H", split_body_len), len(result)))

            if split_begin == len(buf):
                break

        # logging.debug('client_pre_encrypt   >> tcp >> length:%d >> %s' % (len(buf),buf))
        # logging.debug('client_pre_encrypted >> tcp >> length:%d >> %s' % (len(result),result))
        # logging.debug('client_pre_encrypted >> success >> tcp >> length:%d' % len(result))
        # logging.debug('client_pre_encrypted >> success >> tcp >> length:%d >> %s' % (len(result),result))
        return result

    def client_pre_encrypt_mss(self, buf):
        token=self.debug_token

        result = b''
        token_block = bytes([len(token)]) + token

        split_body_len = self.server_info.tcp_mss - len(token_block)

        # split_count = int(len(buf) / split_body_len)
        split_begin = 0

        while split_begin < len(buf):

            if split_begin+split_body_len >= len(buf):
                split_body_len = len(buf) - split_begin

            temp_body_block = struct.pack(">H", split_body_len) + buf[split_begin:split_begin+split_body_len]
            split_begin += split_body_len
            result += token_block + temp_body_block

            if split_begin == len(buf):
                break

        logging.debug('client_pre_encrypt   >> tcp >> length:%d >> %s' % (len(buf),buf))
        logging.debug('client_pre_encrypted >> tcp >> length:%d >> %s' % (len(result),result))
        return result

    def client_encode(self, buf):
        # logging.info('client_encode >> %s' % buf)
        return buf

    def client_decode(self, buf):
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def client_post_decrypt(self, buf):
        logging.debug('client_post_decrypt >> %s' % buf)
        return buf

    # 服务器 => 客户端
    def server_pre_encrypt(self, buf):
        # 此处对raw data进行预处理，之后根据加密方式进行加密
        # logging.debug('server_pre_encrypt >> tcp-buf %s' % buf)
        return buf

    def server_encode(self, buf):
        # logging.info('server_encode >> tcp-buf %s' % buf)
        return buf

    def server_decode(self, buf):
        # logging.info('server_decode >> tcp-buf %s' % buf)
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (buf, True, False)

    # 解密 客户端 => 服务端
    def server_post_decrypt(self, buf):

        body = b''
        is_Body = False
        token = ''
        token_b = b''
        TOKEN_LENGTH_LENGTH=1
        BODY_LENGTH_LENGTH=2
        LENGTH_LENGTH=0
        # len(buf)-1 => 最后一位可读index

        if self.body_remain > 0:
            body_remain = self.body_remain
            if body_remain > len(buf):
                self.body_remain = body_remain - len(buf)
                logging.debug('body_remain >> %d to %d' % (body_remain, self.body_remain))
                return (buf[:body_remain], False, self.uid)
            elif body_remain == len(buf):
                self.body_remain = 0
                logging.debug('body_remain >> %d to %d' % (body_remain, self.body_remain))
                return (buf[:body_remain], False, self.uid)
            else:
                self.body_remain = 0
                logging.debug('body_remain >> %d to %d' % (body_remain, self.body_remain))
                body += buf[:body_remain]
                buf  =  buf[body_remain:]

        if self.token_remain > 0:
            token_remain = self.token_remain

            if self.last_token[:token_remain] != buf[token_remain:]:
                self.token_remain = 0
                raise Exception('Token mismatch buf[%d:] -> %s != self.last_token[:%s] -> %s' % (token_remain, buf[token_remain:], token_remain, self.last_token[:token_remain]))
            buf  =  buf[token_remain:]

            token_b = self.last_token
            token   = token_b.decode('utf8')
            is_Body=True
            self.token_remain = 0

        if self.body_length_remain == 1:
            self.last_body_length.append(buf[0])
            length  =  struct.unpack(">H", self.last_body_length)[0]
            token_b = self.last_token
            token   = token_b.decode('utf8')
            is_Body=False
            self.last_body_length = []
            self.body_length_remain = 0

            LENGTH_LENGTH=BODY_LENGTH_LENGTH

            length_index = 1

            body    += buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]
            is_Body =  False

            logging.debug('server_post_decrypt   > tcp-length_index:%d > body-lenght:%d:%s' % (length_index, length, buf[length_index:length_index+LENGTH_LENGTH]))



        length_index = 0
        logging.debug('server_post_decrypt >> begin >> tcp-length_index >> %d buf:%d' % (length_index, len(buf)))
        while length_index < len(buf) - 1:
            if is_Body==False:
                LENGTH_LENGTH=TOKEN_LENGTH_LENGTH
                length = ord(buf[length_index])

                if token == '':
                    token_b = buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]
                    try:
                        token   = token_b.decode('utf8')
                    except Exception as e:
                        # logging.debug('server_post_decrypt >> failed >> tcp >> %d %s' % (len(buf),buf))
                        logging.debug('server_post_decrypt >> failed >> tcp >> %d' % len(buf))
                        raise Exception('Token decode(utf8) error token_len:%d >> %s' % (length,token_b))
                    if token not in self.server_info.tokens:
                        # print(self.server_info.tokens)
                        # logging.debug('server_post_decrypt >> failed >> tcp >> %d %s' % (len(buf),buf))
                        logging.debug('server_post_decrypt >> failed >> tcp >> %d' % len(buf))
                        raise Exception('Token not found >> %s' % token)
                elif len(token_b) > len(buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]):
                    # token在下一波
                    self.token_remain = len(token_b) - len(buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length])
                    self.last_token   = token_b
                    length_index = len(buf) - 1
                    break

                elif token_b != buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]:
                    raise Exception('Token mismatch >> %s >> %s' % (token_b, buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]))

                is_Body=True
                logging.debug('server_post_decrypt   > tcp-length_index:%d > token-length:%d' % (length_index, length))

                if length_index+LENGTH_LENGTH+length == len(buf):
                    # end
                    break
                elif length_index+LENGTH_LENGTH+length == len(buf)-BODY_LENGTH_LENGTH:
                    raise Exception('Token not found')
                    break
            else:
                LENGTH_LENGTH=BODY_LENGTH_LENGTH

                if length_index+LENGTH_LENGTH == len(buf) + 1:
                    logging.debug('body-lenght splited')
                    self.last_token   = token_b
                    self.last_body_length   = buf[-1:]
                    self.body_length_remain = 1
                    break

                length  =  struct.unpack(">H", buf[length_index:length_index+LENGTH_LENGTH])[0]

                if length_index+LENGTH_LENGTH+length > len(buf):
                    body    += buf[length_index+LENGTH_LENGTH:]
                    self.body_remain = length_index+LENGTH_LENGTH+length - len(buf)
                    break
                    # raise Exception('Error body length not enough length:%s:%d end:%d > len(buf):%d' % (buf[length_index:length_index+LENGTH_LENGTH], length, length_index+LENGTH_LENGTH+length, len(buf)))

                body    += buf[length_index+LENGTH_LENGTH:length_index+LENGTH_LENGTH+length]
                is_Body =  False

                logging.debug('server_post_decrypt   > tcp-length_index:%d > body-lenght:%d:%s' % (length_index, length, buf[length_index:length_index+LENGTH_LENGTH]))

                if length_index+LENGTH_LENGTH+length == len(buf):
                    # end
                    break

            length_index=length_index+LENGTH_LENGTH+length

        # logging.debug('server_post_decrypt >> success >> tcp >> %d to %d' % (len(buf), len(body)))
        # logging.debug('server_post_decrypt >> success >> tcp >> %d %s' % (len(buf),buf))
        # logging.debug('server_post_decrypted >> tcp >> %d %s' % (len(body),body))

        # decrypted_buf, , uid
        self.uid = self.server_info.tokens[token]
        return (body, False, self.server_info.tokens[token])

    def client_udp_pre_encrypt(self,buf):
        token=self.debug_token
        # header 跟body一起，不确定位置，token放后面
        # logging.debug('client_udp_pre_encrypt >> udp-buf %s' % buf)
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
        # print(token_len, buf[:len(buf)-token_len-1], buf[-token_len-1:-1])
        logging.debug('server_udp_post_decrypt => %s' % buf)
        logging.debug('server_udp_post_decrypted => %s' % buf[:len(buf)-token_len-1])
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
