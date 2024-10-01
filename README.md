# SecureProgrammingGroup42
Secure Overlay Chat System following OLAF Protocol

--- GROUP INFO--- 
Group 42
Group Members: a1850028 Kanwartej Singh a1853790 Christian Mahones a1851275 Seung Lee a1849563 Matthew Fuhlbohm

--- DEPENDENCIES --- 
websockets
cryptography
aiohttp
mysql-server

--- RUNNING PROGRAM --- 
The following is dependent on the operating system and machine. However, the following is what is required, as per Ubuntu:

Installing dependencies:

pip install websockets
pip install cryptography
pip install aiohttp
sudo apt install mysql-server
(possibly:) pip install mysql-connector-python

Starting database:
STAR MYSQL -------------- MAKE SURE TO EDIT THIS

Running necessary files: Requires server to be run seperately (seperate terminal)
python3 server_V2.py
python3 app.py
