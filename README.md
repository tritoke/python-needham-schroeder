# python-needham-schroeder
Toy needham-schroeder protocol implementation to explore my cybersecurity course at uni.

# Usage:
Start up the KDC as so: (example run)
```
➜ python kdc.py
Loaded long term keys for users: Alice, Bob, Charlie, Derek
[+] Starting listening on localhost:12345
[KDC] Accepted connection from Bob, requesting to connect to Alice with nonce = 247632538598482949839228182337538123921
```

Start up the listener as whoever is listening (one of Alice, Bob, Charlie, Derek): (example run)
```
➜ python listener.py Alice
[+] Starting listening on localhost:11111
[B] Sending Bob a nonce challenge - nonce = 140379279135590041478187434093260898845.
[B] Success! - Bob passed the nonce test
```

Now with these running we can perform the protocol: (example run)
```
➜ python initiator.py Bob Alice
[A] Initiating protocol with the KDC
Received valid response from KDC, moving on to recipient
Sent shared key to Alice
Answering Alice's nonce challenge.
Decrypted message: You're cute <3
```
