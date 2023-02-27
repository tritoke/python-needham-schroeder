#!/usr/bin/env python

import argparse
import socket
import json
from util import enc, dec, server, load_keyfile, BS, split_at, generate_nonce


KDC_PORT = 12345
RECIPIENT_PORT = 11111


def main():
    parser = argparse.ArgumentParser(
        prog = "Needham-Schroeder Listener",
        description = "Listens for connections then takes part in the needham-schroeder negotiation."
    )
    parser.add_argument("user", help="The user to act as in the negotiation.")
    parser.add_argument("recipient", help="The recipient in the negotiation.")
    parser.add_argument("--key", type=int, help="The long term key", required=False, default=None)

    args = parser.parse_args()
    user = args.user.title()
    recp = args.recipient.title()
    key = args.key

    # if no key was supplied, load one from the long term keys file
    if key is None:
        keys = load_keyfile("long_term_keys.txt")
        key = keys.get(user)

    # oh no!
    if key is None:
        raise Exception(f"Key not provided and no long term key could be found for {user}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", KDC_PORT))

        print(f"[A] Initiating protocol with the KDC")
        nonce = generate_nonce()
        message = json.dumps({
            "initiator": user,
            "listener": recp,
            "nonce": nonce,
        }).encode()
        s.sendall(message)

        # receive data from the KDC
        sent = json.loads(s.recv(1024).decode())

    # recover Kab and check B/Na from sent
    d = dec(bytes.fromhex(sent["message"]), key)
    kab, dest, rx_nonce, msg2 = d.split(b":")

    assert dest.decode() == recp
    assert int(rx_nonce.decode()) == nonce

    print(f"Received valid response from KDC, moving on to recipient")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("localhost", RECIPIENT_PORT))

        print(f"Sent shared key to {recp}")
        message = json.dumps({
            "message": msg2.hex(),
        }).encode()
        s.sendall(message)

        # receive nonce challenge
        sent = json.loads(s.recv(1024).decode())
        challenge = bytes.fromhex(sent["challenge"])
        nb = int(dec(challenge, kab).decode())
        resp = enc(str(nb - 1), kab)
        message = json.dumps({
            "message": resp.hex(),
        }).encode()
        print(f"Answering {recp}'s nonce challenge.")

        s.sendall(message)

        sent = json.loads(s.recv(1024).decode())
        print("Decrypted message:", dec(bytes.fromhex(sent["message"]), kab).decode())


if __name__ == "__main__":
    main()
