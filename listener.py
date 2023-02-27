#!/usr/bin/env python

import argparse
import socket
import json
from util import enc, dec, server, load_keyfile, BS, split_at, generate_nonce

HOST = "localhost"
PORT = 11111


def handle_conn(io, user, key):
    data = io.recv(1024).decode().strip()
    sent = json.loads(data)

    # message = Ekb[Kab||A]
    message = bytes.fromhex(sent["message"])
    message = dec(message, key)

    key_shared, initiator = split_at(message, BS)
    initiator = initiator.decode()
    nonce = generate_nonce()
    print(f"[B] Sending {initiator} a nonce challenge - {nonce = }.")

    message = json.dumps({
        "challenge": enc(str(nonce), key_shared).hex(),
    }).encode()
    io.sendall(message)

    # receiving the challenge
    data = io.recv(1024).decode().strip()
    sent = json.loads(data)

    sent_nonce = int(dec(bytes.fromhex(sent["message"]), key_shared).decode())
    if sent_nonce == nonce - 1:
        print(f"[B] Success! - {initiator} passed the nonce test")
    else:
        raise Exception(f"[B] Fail :( - {initiator} failed the nonce test")

    # send a message back
    message = json.dumps({
        "message": enc("You're cute <3", key_shared).hex(),
    }).encode()
    io.sendall(message)


def main():
    parser = argparse.ArgumentParser(
        prog = "Needham-Schroeder Listener",
        description = "Listens for connections then takes part in the needham-schroeder negotiation."
    )
    parser.add_argument("user", help="The user to act as in the negotiation.")
    parser.add_argument("--key", type=int, help="The long term key", required=False, default=None)

    args = parser.parse_args()
    user = args.user.title()
    key = args.key

    # if no key was supplied, load one from the long term keys file
    if key is None:
        keys = load_keyfile("long_term_keys.txt")
        key = keys.get(user)

    # oh no!
    if key is None:
        raise Exception(f"Key not provided and no long term key could be found for {user}")

    # now listen for connections
    server(HOST, PORT, handle_conn, optional_args=[user, key])


if __name__ == "__main__":
    main()

