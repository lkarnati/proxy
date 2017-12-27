# proxypbproxy

###########~~~~~~~~ Test Environment ~~~~~~~~#############

Linux 4.10.0-38-generic x86_64

Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.3 LTS
Release:	16.04
Codename:	xenial

#############~~~~~~~~~~~ Compiler ~~~~~~~~~~~#############

gcc (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609

############~~~~ How to run the program ~~~~##############

Compile using: $make

First run the server using:
$ ./pbproxy -l 8899 -k mykey localhost 22

#8899 is the pbproxy server port 
#22 is the ssh host port

Next, run the client using:
$ ssh  -o "proxyCommand ./pbproxy -k mykey localhost 8899" localhost

#8899 is the pbproxy server port

~Please follow the order of arguments as given above.
~mykey is the file containing the encryption key.

##############~~~~~ Design of pbproxy ~~~~~~################

pbproxy adds an extra layer of protection using encryption for the connections using TCP.

In server mode (smode), it listens for incoming connections, also once an existing connection
is terminated, it listens for new incoming connections. Initially an IV is exchanged between the 
client and the server. It encrypts/decrypts the incoming data from actual server/client.

In client mode (cmode), it takes input from standard input, encrypts it and sends to the server. 
It also decrypts the incoming data from server and writes it.

Implemented I/O multiplexing using select()
In cmode, select is used to multiplex between the standard input and proxy server.
In smode, select is used to multiplex between the proxy client and the server.

Note: Used AES_ctr128_encrypt() for encryption. So, the key is 16B long.

Both ways, the data is encrypted/decrypted. Initially an IV is communicated and then encryption/decryption follows.

