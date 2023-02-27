#!/usr/bin/env python

import socket
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes


BS = AES.block_size


def server(host, port, handler, optional_args=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # start the listening on localhost:11111
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(10)

        print(f"[+] Starting listening on {host}:{port}")

        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    if isinstance(optional_args, dict):
                        handler(conn, **optional_args)
                    elif isinstance(optional_args, list):
                        handler(conn, *optional_args)
                    else:
                        handler(conn)
                except Exception as e:
                    print(f"[-] Encountered exception handling connection from {addr} - {e}")

def load_keyfile(key_file):
    keys = {}

    with open(key_file) as f:
        for line in f.read().splitlines():
            user, key = line.split(": ")
            key = int(key)

            keys[user] = key.to_bytes(128 // 8, "big")

    return keys


def generate_session_key():
    return get_random_bytes(BS)


def generate_nonce():
    return int.from_bytes(get_random_bytes(BS), "big")


def enc(data, key):
    """
    Encrypt the data with AES-CBC-128

    returns IV||encrypt(pad(data, BS), key)
    """

    if isinstance(data, str):
        data = data.encode("UTF8")

    cipher = AES.new(key, AES.MODE_CBC)
    enc_data = cipher.encrypt(pad(data, BS))

    return cipher.iv + enc_data


def dec(data, key):
    """
    Decrypt the data with AES-CBC-128
    """

    iv, enc_msg = split_at(data, BS)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return unpad(cipher.decrypt(enc_msg), BS)


def split_at(data, boundary):
    return data[:boundary], data[boundary:]
