# SecureProgrammingGroup42
Secure Overlay Chat System following OLAF Protocol

--- GROUP INFO--- 

Group 42

Group Members: a1850028 Kanwartej Singh, a1853790 Christian Mahones, a1851275 Seung Lee, a1849563 Matthew Fuhlbohm

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

START MYSQL -------------- MAKE SURE TO EDIT THIS
To check the status of mysql run:
sudo service mysql status


Running necessary files: Requires server to be run seperately (seperate terminal)


python3 server_V2.py

python3 app.py

---RUNNING THE CHAT SYSTEM---

The client will prompt the user with six different commands, which can be accessed by entering the numbers 1-6.
Entering (1) will allow the user to send a private chat, and the client will print out the fingerprints of the current online users, and will then prompt the user to enter the fingerprint(s) of the users that the message will go to. These can be copy-and-pasted from the fingerprints that the client prints to the interface. The desired message can then be entered into the following prompt, and the message will be sent to the server.

Entering (2) will allow the user to send a public chat, and will prompt the user to enter the desired message to send to every online user. 

Entering (3) will allow the user to upload a file for file transfer. It will prompt the user for the file path of the file that will be uploaded. It will then return and print a file url that can be used to download the file at a later time.

Entering (4) will allow the user to download a file. It will prompt the user to enter the url of the file to download (received from file upload), and also the path the file will be downloaded to. It will then download the file and save it to the desired destination. 

Entering (5) will allow the user to manually update the client list and show the currently online users. It will print all the fingerprints of the users currently online (as a base64 encoded string).

Entering (6) will disconnect the user from the server.

Notes: The client list will automatically update every 30 seconds, to ensure the client at least has a relatively recent version of the client list. It may be a good idea to update the client list manually to ensure that it can receive/send messages properly.


