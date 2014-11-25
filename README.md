jSC - Java Secure Chat
======================

jSC is a end-to-end chat application, written in Java.

# How it works

One user act as a server. Listen on localhost on a selected port.

The other user act as a client: connect to the address of the of the server on the selected port.

# Message sequence

1. Client send its RSA public key to the client
2. Server send its RSA public key to the client 
3. Server generate AES seed and sent it to the client, encrypted with the client public key. Server setup AES cipher using the generated seed as IV.
4. Client receive AES decrypt this Seed using his private key and inizialize AES cipher with the received seed.
5. Successive communications are encrypted using AES, in CBC mode, using PKCS5 padding standard.
