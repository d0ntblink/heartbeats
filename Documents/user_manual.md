# Heartbeats User Guide
### Gary Khodayari 27th, Feb 2022

[Github Link](https://github.com/d0ntblink/heartbeats)

### Requirements

Programs
  * Python3

Python Liberaries:
  * scapy
  * threading (existing)
  * time (existing)
  * random (existing)

*Optional:*
  * *python3-pip*

Copy and paste the command below to install all the Python3 liberaries.
```
sudo pip3 install scapy
or
sudo python3-pip install scapy
or
sudo pip install scapy
```
Check to see your your python and pip version
```
python3 --version
pip3 --version
```

### Usage

#### Server Side
```
git clone https://github.com/d0ntblink/heartbeats
cd heartbeats/Server/
python3 server.py
```

#### Client Side
```
git clone https://github.com/d0ntblink/heartbeats
cd heartbeats/Client/
python3 server.py
```

#### Debug Mode
**To enable debug mode in either program:**
1) Comment the line below
```
logging.basicConfig(level=logging.INFO,
                    format='\n%(asctime)s : %(threadName)s -- %(message)s\n') 
```
2) Uncomment the line below
```
# logging.basicConfig(level=logging.DEBUG,
#                     format='\n%(asctime)s : %(threadName)s -- %(message)s\n')
```