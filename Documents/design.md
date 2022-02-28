You will need two seperate machines, a server and client to run this application.
this program needs to be ran as root on both machines.

This program will only support one session at a time.


Client Side:
client.py program runs as root with a IP and port as arguments. client will intiated the TCP handshake with server which should be already listening on the designated port. after the handshake is succesfully done, the client is able to send messages  less than 1024 bits. if the message is TERMINATE, then the TCP session is ended with a FIN packet.

while the handshake is still open, client will have seprate thread listening for HEARTBEAT packets and answer them back with STILL_DRE.

client will use scapy to create TCP packets.


Server Side:
before client.py is ran, server.py should be already running and listening on a designated port. server.py accepts the 3 way TCP handshake and keeps the session open. whenever the server gets a PSH packets and prints the information about it. if the packets has TERMINATE in it, the session will close. if the server hasnt recieved anything in the past 60 seconds, it will send a HEARTBEAT packet on a diffrent thread and listens for a answer to make sure the client is still alive.