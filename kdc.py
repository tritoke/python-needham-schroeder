#!/usr/bin/env python

import socket
import json
from util import enc, dec, server, load_keyfile, generate_session_key


HOST = "localhost"
PORT = 12345
DATABASE = load_keyfile("long_term_keys.txt")


def handle_conn(io):
    data = io.recv(1024).decode().strip()
    sent = json.loads(data)

    a = sent["initiator"]
    ka = DATABASE[a]
    b = sent["listener"]
    kb = DATABASE[b]
    nonce = sent["nonce"]

    print(f"[KDC] Accepted connection from {a}, requesting to connect to {b} with {nonce = }")

    kab = generate_session_key()
    message = enc(
        kab
        + b":"
        + b.encode()
        + b":"
        + str(nonce).encode()
        + b":"
        + enc(kab + a.encode(), kb),
        ka
    )

    message = json.dumps({
        "message": message.hex(),
    }).encode()

    io.sendall(message)
    io.close()


def main():
    print("Loaded long term keys for users:", ", ".join(DATABASE))

    server(HOST, PORT, handle_conn)


if __name__ == "__main__":
    main()
