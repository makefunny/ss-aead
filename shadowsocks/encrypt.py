#!/usr/bin/env python
#
# Copyright 2012-2015 clowwindy
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

from shadowsocks import common
from shadowsocks.crypto import rc4_md5, openssl, sodium, table


CIPHER_ENC_ENCRYPTION = 1
CIPHER_ENC_DECRYPTION = 0

METHOD_INFO_KEY_LEN = 0
METHOD_INFO_IV_LEN = 1
METHOD_INFO_CRYPTO = 2

method_supported = {}
method_supported.update(rc4_md5.ciphers)
method_supported.update(openssl.ciphers) # include aead
method_supported.update(sodium.ciphers)  # chacha20 series
method_supported.update(table.ciphers)   # table and none


def random_string(length):
    return os.urandom(length)


cached_keys = {}


def try_cipher(key, method=None, crypto_path=None):
    Encryptor(key, method, crypto_path)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    if r:
        return r
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    cached_keys[cached_key] = (key, iv)
    return key, iv


class Encryptor(object):
    def __init__(self, password, method, crypto_path = None, iv = None):
        """
        Crypto wrapper
        :param password: str cipher password
        :param method: str cipher
        :param crypto_path: dict or none
            {'openssl': path, 'sodium': path, 'mbedtls': path}
        """
        self.password = password
        self.key = None
        self.method = method
        self.iv_sent = False
        self.cipher_iv = b''
        self.iv_buf = b'' # ssrspeed
        self.decipher = None
        self.decipher_iv = None
        self.crypto_path = crypto_path
        # logging.debug(self.crypto_path)
        method = method.lower()
        self._method_info = Encryptor.get_method_info(method)
        # logging.debug(self._method_info)
        if self._method_info:
            if iv is None or len(iv) != self._method_info[1]:
                self.cipher = self.get_cipher(
                    password,   method,
                    CIPHER_ENC_ENCRYPTION,
                    random_string(self._method_info[METHOD_INFO_IV_LEN]))
            else:
                if self.key:
                    self.cipher = self.get_cipher(
                        self.key,      method,
                        CIPHER_ENC_ENCRYPTION,
                        iv)
                else:
                    self.cipher = self.get_cipher(
                        self.password, method,
                        CIPHER_ENC_ENCRYPTION,
                        iv)
        else:
            logging.error('method %s not supported' % method)
            # sys.exit(1)
            raise Exception('method not supported')

    @staticmethod
    def get_method_info(method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    def get_cipher(self, password, method, op, iv):
        password = common.to_bytes(password)
        m = self._method_info
        if m[METHOD_INFO_KEY_LEN] > 0:
            key, _ = EVP_BytesToKey(password, m[METHOD_INFO_KEY_LEN], m[METHOD_INFO_IV_LEN])
        else:
            # key_length == 0 indicates we should use the key directly
            key, iv = password, b''
        # logging.warn(len(key))
        # logging.warn(op)
        self.key = key
        iv = iv[:m[METHOD_INFO_IV_LEN]]
        if op == CIPHER_ENC_ENCRYPTION:
            # this iv is for cipher, not decipher
            self.cipher_iv = iv
        return m[METHOD_INFO_CRYPTO](method, key, iv, op, self.crypto_path)

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.iv_sent:
            # return self.cipher.encrypt(buf)
            return self.cipher.encrypt(buf)
        else:
            self.iv_sent = True
            # return self.cipher_iv + self.cipher.encrypt(buf)
            return self.cipher_iv + self.cipher.encrypt(buf)

    def decrypt(self, buf):
        # logging.debug("decrypt >> %d %s %s" % (len(buf),self.password, self.method))
        if len(buf) == 0:
            return buf

        if self.decipher is not None: #optimize
            # aead methods update(AeadCryptoBase) will lead to error => 
            # return self.decipher.update(buf)
            return self.decipher.decrypt(buf)

        decipher_iv_len = self._method_info[1]
        if len(self.iv_buf) <= decipher_iv_len:
            self.iv_buf += buf
        if len(self.iv_buf) > decipher_iv_len:
            decipher_iv = self.iv_buf[:decipher_iv_len]
            self.decipher = self.get_cipher(
                self.password, self.method,
                CIPHER_ENC_DECRYPTION,
                decipher_iv)
            # logging.warn(self.decipher)
            buf = self.iv_buf[decipher_iv_len:]
            del self.iv_buf
            return self.decipher.decrypt(buf)
        else:
            return b''

    def decrypt_origin(self, buf):
        # print(self.password)
        if len(buf) == 0:
            return buf
        if self.decipher is None:
            decipher_iv_len = self._method_info[METHOD_INFO_IV_LEN]
            decipher_iv = buf[:decipher_iv_len]
            self.decipher_iv = decipher_iv
            self.decipher = self.get_cipher(
                self.password, self.method,
                CIPHER_ENC_DECRYPTION,
                decipher_iv)
            # logging.debug("decipher_iv_len >> %d" % decipher_iv_len)
            buf = buf[decipher_iv_len:]
            if len(buf) == 0:
                return buf
        return self.decipher.decrypt(buf)


def gen_key_iv(password, method):
    method = method.lower()
    if method not in method_supported:
        raise Exception('method not supported')
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    iv = random_string(iv_len)

    return key, iv, m


def encrypt_all_m(key, iv, m, method, data, crypto_path=None):
    result = [iv]
    cipher = m(method, key, iv, 1, crypto_path)
    result.append(cipher.encrypt_once(data))
    return b''.join(result)


def decrypt_all(password, method, data, crypto_path=None):
    # print(password, data)
    result = []
    method = method.lower()
    (key, iv, m) = gen_key_iv(password, method)
    iv = data[:len(iv)]
    # data = data[len(iv):]
    cipher = m(method, key, iv, CIPHER_ENC_DECRYPTION, crypto_path)
    result.append(cipher.decrypt_once(data[len(iv):]))
    return b''.join(result), key, iv


def encrypt_all(password, method, data, crypto_path=None):
    result = []
    method = method.lower()
    (key, iv, m) = gen_key_iv(password, method)
    result.append(iv)
    cipher = m(method, key, iv, CIPHER_ENC_ENCRYPTION, crypto_path)
    result.append(cipher.encrypt_once(data))
    return b''.join(result)

def encrypt_key(password, method):
    method = method.lower()
    if method not in method_supported:
        raise Exception('method not supported')
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    return key

def encrypt_iv_len(method):
    method = method.lower()
    if method not in method_supported:
        raise Exception('method not supported')
    (key_len, iv_len, m) = method_supported[method]
    return iv_len

def encrypt_new_iv(method):
    method = method.lower()
    if method not in method_supported:
        raise Exception('method not supported')
    (key_len, iv_len, m) = method_supported[method]
    return random_string(iv_len)

CIPHERS_TO_TEST = [
    'aes-128-cfb',
    'aes-256-cfb',
    'aes-128-gcm',
    'aes-256-gcm',
    'rc4-md5',
    'salsa20',
    'chacha20',
    'table',
]


def test_encryptor():
    from os import urandom
    plain = urandom(10240)
    key = b'key'
    for method in CIPHERS_TO_TEST:
        logging.warn("key >> %s method >> %s" % (key, method))
        encryptor = Encryptor(key, method)
        decryptor = Encryptor(key, method)
        cipher = encryptor.encrypt(plain)
        plain2 = decryptor.decrypt(cipher)
        assert plain == plain2


def test_encrypt_all():
    from os import urandom
    plain = urandom(10240)
    # plain = b"asdasdsadasd"
    init_key = b'key'
    for method in CIPHERS_TO_TEST:
        logging.warn("init_key >> %s method >> %s" % (init_key, method))
        cipher = encrypt_all(init_key, method, plain)
        plain2, key, iv = decrypt_all(init_key, method, cipher)
        assert plain == plain2


def test_encrypt_all_m():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        key, iv, m = gen_key_iv(b'key', method)
        cipher = encrypt_all_m(key, iv, m, method, plain)
        plain2, key, iv = decrypt_all(b'key', method, cipher)
        assert plain == plain2


if __name__ == '__main__':
    test_encryptor()
    test_encrypt_all()
    test_encrypt_all_m()
