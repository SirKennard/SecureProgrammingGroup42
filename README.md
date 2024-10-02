# Secure Programming 3307: Group 42 Implemenation
Secure Overlay Chat System following OLAF Neighbourhood Protocol

Members: 
- a1850028 Kanwartej Singh
- a1853790 Christian Mignone
- a1851275 Seung Lee
- a1849563 Matthew Fuhlbohm

## Dependencies and Setup
**NOTE: This guide is for Ubuntu/Debian based Linux distributions. If you are running a different OS please consult the appropriate documentation online.**
### Python Packages:
**NOTE: Please ensure you have Python >= 3.10.0**\
Install required Python packages with `python3 -m pip install -r requirements.txt`

### MySQL setup:

- If on ubuntu/debian:
`sudo apt install mysql-server` to install MySQL. For other distros/OS check the respective documentation.

- Check if the server is running. `sudo systemctl status mysql.service` or `sudo service mysql status`

- Change authenticaion parameters to give root a password: `sudo mysql`. Then at the prompt `ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'olafclient';`

- Change MySQL security settings. `sudo mysql_secure_installation`. Select **no** at each prompt, but **yes** at ***"Reload privilege tables now?"*** (the last prompt).

- Install Python MySQL driver. `python3 -m pip install mysql-connector-python`

The server requires a specific file layout in order to run. Please ensure you have the following directory structure.
```
├── server.py
├── handlers/
│   ├── __init__.py
│   └── format_message.py
├── local/
│   ├── client_list.json (auto-generated)
│   ├── server.log (auto-generated)
│   ├── server_neighbourhood.json (required for server to start)
│   ├── server_private_key.pem (auto-generated)
│   └── server_public_key.pem (auto-generated)
├── uploads/
│   └── files that are uploaded
└── utils/
    ├── __init__.py
    ├── init_keys.py
    └── RSA.py
```
An empty `server_neighbourhood.json` file is included in this repository. **This file is required for the server to start**. Please fill it out with the server's respecive websockets uri and public key. An example looks like this:
```json
{
    "servers": [
        {
            "uri": "ws://127.0.0.1:8888",
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjA...DAQAB\n-----END PUBLIC KEY-----"
        }
    ]
}
```

## Running The Program

- Check if MySQL server is running with `sudo systemctl status mysql.service` or `sudo service mysql status`. If not start it with `sudo systemctl start mysql.service` or `sudo service mysql start`
- 


Running necessary files: Requires server to be run seperately (seperate terminal)


python3 server_V2.py

python3 app.py

## Running the Chat System

- The client will prompt the user with six different commands, which can be accessed by entering the numbers 1-6.

- Entering (1) will allow the user to send a private chat, and the client will print out the fingerprints of the current online users, and will then prompt the user to enter the fingerprint(s) of the users that the message will go to. These can be copy-and-pasted from the fingerprints that the client prints to the interface. The desired message can then be entered into the following prompt, and the message will be sent to the server.

- Entering (2) will allow the user to send a public chat, and will prompt the user to enter the desired message to send to every online user. 

- Entering (3) will allow the user to upload a file for file transfer. It will prompt the user for the file path of the file that will be uploaded. It will then return and print a file url that can be used to download the file at a later time.

- Entering (4) will allow the user to download a file. It will prompt the user to enter the url of the file to download (received from file upload), and also the path the file will be downloaded to. It will then download the file and save it to the desired destination. 

- Entering (5) will allow the user to manually update the client list and show the currently online users. It will print all the fingerprints of the users currently online (as a base64 encoded string).

- Entering (6) will disconnect the user from the server.

Note: The client list will automatically update every 30 seconds, to ensure the client at least has a relatively recent version of the client list. It may be a good idea to update the client list manually to ensure that it can receive/send messages properly.


