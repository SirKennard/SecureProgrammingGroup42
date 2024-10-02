# Secure Programming 3307: Group 42 Implemenation
Secure Overlay Chat System following OLAF Neighbourhood Protocol

Members: 
- a1850028 Kanwartej Singh
- a1853790 Christian Mignone
- a1851275 Seung Lee
- a1849563 Matthew Fuhlbohm

## Dependencies and Setup
**NOTE: This guide is for Ubuntu/Debian based Linux distributions. If you are running a different OS please consult the appropriate documentation online. We recommend using Ubuntu/Debian or an alternative Linux distribution.**
### Python Packages:
**NOTE: Please ensure you have Python >= 3.10.0**\
Install required Python packages with `python3 -m pip install -r requirements.txt`
If you do not have Python installed, install it with `sudo apt install python3`

### MySQL setup:

**MySQL is only required for the client, if you are running a server on a seperate machine skip this setup.**

1. Run `sudo apt update && sudo apt upgrade -y` to update the system if not updated recently. 

2. If on ubuntu/debian:
`sudo apt install mysql-server` to install MySQL. For other distros/OS check the respective documentation.

3. Check if MySQL server is running with `sudo systemctl status mysql.service` or `sudo service mysql status`. If not start it with `sudo systemctl start mysql.service` or `sudo service mysql start`

4. Change authenticaion parameters to give root a password: `sudo mysql`. Then at the prompt `ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'olafclient';`

5. Type `exit` to close the MySQL shell

6. Change MySQL security settings. `sudo mysql_secure_installation`. Select **no** at each prompt, but **yes** at ***"Reload privilege tables now?"*** (the last prompt).

7. Install Python MySQL driver. `python3 -m pip install mysql-connector-python`

### Server Directory Setup:

The server requires a specific file layout in order to run. Please ensure you have the following directory structure. If you wish to run multiple servers, they all must have a seperate directory structure, you cannot simply have multiple servers sharing the one set of directories. 
```
├── server.py
├── handlers/
│   ├── __init__.py
│   └── format_message.py
├── local/
│   ├── client_list.json (auto-generated)
│   ├── server.log (auto-generated)
|   ├── upload.log (auto-generated)
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
All files marked with (auto-generated) do not need to be present for the server to start and will be generated upon startup (one exception is `server_private_key.pem` and `server_public_key.pem` please read below for further details).

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
If `server_private_key.pem` and `server_public_key.pem` do not exist, they will be generated on server startup. Please note that if `server_neighbourhood.json` is not populated the server will crash, **if you are only running the server to generate the keys it is ok if this occurs**. Alternatively, to avoid this the public and private keys can be generated prior to running the server via openssl. To generate the private key: 
```
openssl genpkey -algorithm RSA -out server_private_key.pem -pkeyopt rsa_keygen_bits:2048`
```
The public key is generated with:
```
openssl rsa -pubout -in server_private_key.pem -out server_public_key.pem
```
Move these keys into the appropriate directory as mentioned above.

## Running The Program

### Server:
1. Ensure the directory structure outlined about is correct and the python dependencies are installed, these can be checked with `python3 -m pip list`.
2. Ensure the `server_neighbourhood.json` is correctly filled out with the server uri and public key.
3. To start the server run `python3 server.py <server ip address> <server port>`, where the IP and port are parsed as arguments.

### Client:
1. Check if MySQL server is running with `sudo systemctl status mysql.service` or `sudo service mysql status`. If not start it with `sudo systemctl start mysql.service` or `sudo service mysql start`
2. To start the client run `python3 client_app.py`

### Debugging: VS Code/Pylance/Pylint not resolving import
If the imports are not being resolve in your editor, you may have to install all the Dependencies in a virtual envrionement. To setup a virtual environment in python, you must do the following:
1. Install virtual environment `pip3 install virtualenv`
2. Activate the virutal environment `python3 -m venv env`
3. Activate it: `source env/bin/activate`
4. It will have (env) before your command line!
5. Then `pip install -r requirements.txt`
6. Finally, install any other dependencies required.
