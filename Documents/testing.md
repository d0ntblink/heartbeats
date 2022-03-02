# Heartbeats Testing
### Gary Khodayari 27th, Feb 2022

[Github Link](https://github.com/d0ntblink/heartbeats)

***Some of the examples are from the Debug Mode since the debug mode displays the process of the program a lot better and more verbosely. For a look at the non debug mode version of the code, Please either run the code in normal operation mode or watch the accompanied video.***

***Thank you,<br>***
***Gary***

[***JUMP TO CLIENT***](#client)

[***JUMP TO SERVER***](#server)

## Client

| ***Function*** | ***Description*** | ***Status*** | ***Example*** |
|:-------------------|:--------------------------------:|:--------------:|----------:|
| Import Liberaries | Program imports required liberaries | *Passed* |
| Logging Implemented | Instead of printing, I will use logging for cleaner look and timestamps | *Passed* |
| Debug Mode | There is a debug mode implemented that displays usefull information for debugging | *Passed* | [Example](#debug-mode)
| BR Filter | Program correctly detects its own IP and creates a BPF filter isolating correct packets | *Passed* |
| Welcome Page | A welcome intro is displayed when the program is first opened | *Passed* | [Example](#welcome-page)
| Local IP | Local IP is displayed once when time the program has started | *Passed* | [Example](#local-ip)
| Thread Maker | The thread maker function is implement | *Passed* |
| UI | There is a comprehensive user interface display | *Passed* | [Example](#ui)
| Messenger | One thread is responsible for grabing user input from UI and sending the message to the server | *Passed* | [Example](#messenger)
| Termination | Termination option correctly terminates heartbeat sessions | *Passed* | [Example](#termination)
| Pulse Receiving and Responding | Pulse messages are correctly received and responded to | *Passed* | [Example](#pulse-receiving-and-respondig)
| Incorrect Input handling | Incorrect inputs dont break the program | *Passed* | [Example](#incorect-input-handling)

## Examples
### Debug Mode
```
2022-03-02 05:24:27,900 : Thread-2 -- <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0> <Results: TCP:1 UDP:0 ICMP:0 Other:0>


2022-03-02 05:24:27,901 : Thread-2 -- Responded back to the PULSE from 10.0.0.231


2022-03-02 05:25:27,893 : Thread-2 -- looking_for_pulse is starting ...


2022-03-02 05:25:27,893 : Thread-2 -- Ether / IP / TCP 10.0.0.231:17665 > 10.0.0.232:11415 S


2022-03-02 05:25:27,930 : Thread-2 -- looking_for_pulse is starting ...


2022-03-02 05:25:27,930 : Thread-2 -- Ether / IP / TCP 10.0.0.231:17665 > 10.0.0.232:11415 A


2022-03-02 05:25:27,962 : Thread-2 -- looking_for_pulse is starting ...


2022-03-02 05:25:27,962 : Thread-2 -- Ether / IP / TCP 10.0.0.231:17665 > 10.0.0.232:11415 A / Raw


2022-03-02 05:25:27,962 : Thread-2 -- Recieved a Pulse from 10.0.0.231


2022-03-02 05:25:27,962 : Thread-2 -- send_msg is starting ...
```
### Welcome Page
```
 ___  ___  _______   ________  ________  _________      
|\  \|\  \|\  ___ \ |\   __  \|\   __  \|\___   ___\    
\ \  \\\  \ \   __/|\ \  \|\  \ \  \|\  \|___ \  \_|    
 \ \   __  \ \  \_|/_\ \   __  \ \   _  _\   \ \  \     
  \ \  \ \  \ \  \_|\ \ \  \ \  \ \  \\  \|   \ \  \    
   \ \__\ \__\ \_______\ \__\ \__\ \__\\ _\    \ \__\   
    \|__|\|__|\|_______|\|__|\|__|\|__|\|__|    \|__|   
                                                        
                                                        
                                                        
 ________  _______   ________  _________  ________      
|\   __  \|\  ___ \ |\   __  \|\___   ___\\   ____\     
\ \  \|\ /\ \   __/|\ \  \|\  \|___ \  \_\ \  \___|_    
 \ \   __  \ \  \_|/_\ \   __  \   \ \  \ \ \_____  \   
  \ \  \|\  \ \  \_|\ \ \  \ \  \   \ \  \ \|____|\  \  
   \ \_______\ \_______\ \__\ \__\   \ \__\  ____\_\  \ 
    \|_______|\|_______|\|__|\|__|    \|__| |\_________\
                                            \|_________|
                                                        

Welcome to the Heartbeats Client!
Before sending messages, make sure the heartbeats server is already running and reachable.
You can Access the most up-to-date version on: https://github.com/d0ntblink/heartbeats
```
### Local IP
```
2022-03-02 05:13:17,173 : MainThread -- local ip : 10.0.0.232
```
### UI
```
Please input the ip address of the server you are trying to connect to: 10.0.0.231

What would like to do:
S) Send a customized message ->
Q) Terminate session and change server IP ->
E) Exit the program (REMOVED. DO NOT USE) ->

S

What is your message : Whats up Doc?
```
### Messenger
```
What is your message : hello

Begin emission:
Finished sending 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
.
Sent 1 packets.
Begin emission:
Finished sending 1 packets.
*........................
Received 25 packets, got 1 answers, remaining 0 packets

2022-03-02 05:26:20,785 : Thread-1 -- Message Sent!
```
### Termination
```
q

Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
.
Sent 1 packets.
Begin emission:
Finished sending 1 packets.
*......................
Received 23 packets, got 1 answers, remaining 0 packets

2022-03-02 05:26:58,017 : Thread-1 -- sent a terminate command
```
### Pulse Receiving and Responding
```
2022-03-02 05:21:23,214 : Thread-2 -- Recieved a Pulse from 10.0.0.231

2022-03-02 05:21:24,309 : Thread-2 -- Responded back to the PULSE from 10.0.0.231
```
### Incorrect Input handling
```
What would like to do:
S) Send a customized message ->
Q) Terminate session and change server IP ->
E) Exit the program (REMOVED. DO NOT USE) ->

ll

2022-03-02 05:20:43,287 : Thread-1 -- Unknown Input, Please try again!
```

## Server

| ***Function*** | ***Description*** | ***Status*** | ***Example*** |
|:-------------------|:--------------------------------:|:--------------:|----------:|
| Import Liberaries | Program imports required liberaries | *Passed* |
| Logging Implemented | Instead of printing, I will use logging for cleaner look and timestamps | *Passed* |
| Debug Mode | There is a debug mode implemented that displays usefull information for debugging | *Passed* | [Example](#server-sebug-mode) |
| BR Filter | Program correctly detects its own IP and creates a BPF filter isolating correct packets | *Passed* |
| Welcome Page | A welcome intro is displayed when the program is first opened | *Passed* | [Example](#server-welcome-page) |
| Local IP | Local IP is displayed once when time the program has started | *Passed* | [Example](#server-local-ip) |
| Thread Maker | The thread maker function is implement | *Passed* |
| User Chosen Timeout | Server users asks for its heartbeat session timeout limit and uses it | *Passed* |  [Example](#user-chosen-timeout) |
| Accepting Messages | The server accepts messages and displays to the terminal | *Passed* | [Example](#accepting-messages)
| Heartbeat Counter | Program correctly keeps count of the time passed the last time it received a message from every of its heartbeat session companions | *Passed* | [Example](#heartbeat-counter) |
| Heartbeat Retry | The server tries to contact the client for a user chosen amount. | *Passed* | [Example](#heartbeat-retry) |
| Heartbeat Give Up | After the user chose amount of Pulse have been sent, server will give up and close the session. | *Passed* | [Example](#heartbeat-give-up) |
| Termination | When Server Receives a terminate command it will close active heartbeat session for the soruce ip | *Passed* | [Example](#server-termination) |
| Pulse Sending | Server sends a Pulse everytime a heartbeat session is timedout | *Passed* | [Example](#pulse-sending) |
| Incorrect Input handling | Incorrect inputs dont break the program | *Passed* |  [Example](#server-incorrect-input-handling) |
| Multiple Clients | Accept messages From multiple Sources and keep heartbeat countdown for all | *Passed* |  [Example](#server-multiple-clients) |

## Examples
### Server Debug Mode
```
How long should the server wait before sending a PULSE? (in seconds) 4


Listening for messages ....

2022-03-02 05:31:06,564 : MainThread -- timeout limit is 4.


2022-03-02 05:31:06,564 : MainThread -- start_a_thread is starting ...


2022-03-02 05:31:06,564 : Thread-1 -- listening_for_pkts starting ...


2022-03-02 05:31:06,564 : MainThread -- created thread <Thread(Thread-1, started 140323487831616)>.


2022-03-02 05:31:06,564 : MainThread -- start_a_thread is starting ...


2022-03-02 05:31:06,566 : Thread-2 -- heartbeat is starting ...


2022-03-02 05:31:06,566 : MainThread -- created thread <Thread(Thread-2, started 140323479438912)>.
```
### Server Welcome Page
```
 ___  ___  _______   ________  ________  _________      
|\  \|\  \|\  ___ \ |\   __  \|\   __  \|\___   ___\    
\ \  \\\  \ \   __/|\ \  \|\  \ \  \|\  \|___ \  \_|    
 \ \   __  \ \  \_|/_\ \   __  \ \   _  _\   \ \  \     
  \ \  \ \  \ \  \_|\ \ \  \ \  \ \  \\  \|   \ \  \    
   \ \__\ \__\ \_______\ \__\ \__\ \__\\ _\    \ \__\   
    \|__|\|__|\|_______|\|__|\|__|\|__|\|__|    \|__|   
                                                        
                                                        
                                                        
 ________  _______   ________  _________  ________      
|\   __  \|\  ___ \ |\   __  \|\___   ___\\   ____\     
\ \  \|\ /\ \   __/|\ \  \|\  \|___ \  \_\ \  \___|_    
 \ \   __  \ \  \_|/_\ \   __  \   \ \  \ \ \_____  \   
  \ \  \|\  \ \  \_|\ \ \  \ \  \   \ \  \ \|____|\  \  
   \ \_______\ \_______\ \__\ \__\   \ \__\  ____\_\  \ 
    \|_______|\|_______|\|__|\|__|    \|__| |\_________\
                                            \|_________|
                                                        

Welcome to the Heatbeats Server!
Please make sure your heartbeats server is reachable by your clients.
Heartbeats server is only made of one way client to server communication.
Heartbeats sessions are not real TCP sessions, this is done to avoid the need to configure your firewall.
You can Access the most up-to-date version on: https://github.com/d0ntblink/heartbeats
```
### Server Local IP
```
2022-03-02 05:11:18,836 : MainThread -- local ip : 10.0.0.231
```
### User Chosed Timeout
```
How long should the server wait before sending a PULSE? (in seconds) 30
How many PULSEs should the server send before giving up? 15

Listening for messages ....
```
### Accepting Messages
```
2022-03-02 05:15:27,874 : Thread-1 -- heartbeat session with 10.0.0.232 has been opened


2022-03-02 05:15:27,946 : Thread-1 -- 10.0.0.232 said Whats up Doc?

```
### Heartbeat Counter
```
2022-03-02 05:19:30,175 : Thread-1 -- 10.0.0.232 said Whats up Doc?

2022-03-02 05:19:30,175 : Thread-1 --
-- Ether INFO --
ip proto : 2048
-- IP INFO --
dst ip : 10.0.0.231
src ip : 10.0.0.232
ip ver : 4
pkt size : 53
-- TCP INFO --
tcp flag: A
src port : 42063
dest port : 11414
data : b'Whats up Doc?'


2022-03-02 05:19:30,936 : Thread-2 -- 10.0.0.232 hasnt replied for 1 seconds


2022-03-02 05:19:31,937 : Thread-2 -- 10.0.0.232 hasnt replied for 2 seconds


2022-03-02 05:19:32,938 : Thread-2 -- 10.0.0.232 hasnt replied for 3 seconds


2022-03-02 05:19:33,939 : Thread-2 -- 10.0.0.232 hasnt replied for 4 seconds


2022-03-02 05:19:34,940 : Thread-2 -- 10.0.0.232 hasnt replied for 5 seconds


2022-03-02 05:19:35,942 : Thread-2 -- 10.0.0.232 hasnt replied for 6 seconds
```
### Heartbeat Retry
```
2022-03-02 06:44:51,299 : Thread-2 -- Session with 10.0.0.232 timedout.

2022-03-02 06:44:52,405 : Thread-2 -- Sent a pulse to 10.0.0.232.

2022-03-02 06:45:03,517 : Thread-2 -- Sent a pulse to 10.0.0.232.

2022-03-02 06:45:14,653 : Thread-2 -- Sent a pulse to 10.0.0.232.

2022-03-02 06:45:16,756 : Thread-2 -- Sent a pulse to 10.0.0.232.

```
### Heartbeat Give Up
```
2022-03-02 06:45:20,948 : Thread-2 -- Sent a pulse to 10.0.0.232.

2022-03-02 06:45:21,950 : Thread-2 -- giving up on 10.0.0.232.

2022-03-02 06:45:21,950 : Thread-2 -- heartbeat session with 10.0.0.232 has been closed
```
### Server Termination
```
2022-03-02 05:26:57,002 : Thread-1 -- heartbeat session with 10.0.0.232 has been closed
```
### Pulse Sending
```
2022-03-02 05:25:27,845 : Thread-2 -- Session with 10.0.0.232 timedout.

Begin emission:
Finished sending 1 packets.
..*
Received 3 packets, got 1 answers, remaining 0 packets
.
Sent 1 packets.
Begin emission:
Finished sending 1 packets.
*..

2022-03-02 05:25:28,981 : Thread-2 -- Sent a pulse to 10.0.0.232.

2022-03-02 05:25:28,054 : Thread-1 -- 10.0.0.232 said STILL D.R.E
```
### Server Incorrect Input handling
```

How long should the server wait before sending a PULSE? (in seconds) jfjjfjfjf

2022-03-02 05:30:51,249 : MainThread -- Something went wrong, try again.

How long should the server wait before sending a PULSE? (in seconds) 4

Listening for messages ....
```
### Multiple Clients
```
2022-03-02 05:33:30,936 : Thread-2 -- 10.0.0.232 hasnt replied for 5 seconds


2022-03-02 05:33:30,937 : Thread-2 -- 10.0.0.233 hasnt replied for 11 seconds


2022-03-02 05:33:31,938 : Thread-2 -- 10.0.0.232 hasnt replied for 6 seconds


2022-03-02 05:33:31,939 : Thread-2 -- 10.0.0.233 hasnt replied for 12 seconds


2022-03-02 05:33:32,940 : Thread-2 -- 10.0.0.232 hasnt replied for 7 seconds


2022-03-02 05:33:32,942 : Thread-2 -- 10.0.0.233 hasnt replied for 13 seconds
```
