from cryptography.hazmat.primitives import serialization
from Client import Client
from RSA import RSA
import asyncio
import mysql.connector
import textwrap
import hashlib
import base64

BOLD = '\033[1m'
END = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'

def manage_db(database):
    # Create connection to database
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="olafclient"
    )

    # Create a database if it doesnt already exist 
    if connection.is_connected():
        cursor = connection.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")

        # Select database
        cursor.execute(f"USE {database}")   

        # Create a users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            fingerprint MEDIUMTEXT NOT NULL,
            password VARCHAR(255) NOT NULL,
            private_key MEDIUMTEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        connection.commit()

    return connection

def login(connection):
    cursor = connection.cursor()

    while True:
        fingerprint = input(f"{BOLD}Enter your fingerprint: {END}")
        password = input(f"{BOLD}Enter your password: {END}")

        query = f"""SELECT private_key FROM users WHERE fingerprint = '{fingerprint}' AND password = '{password}'"""

        try:
            cursor.execute(query)
            db_private_key = cursor.fetchone()

            if not db_private_key:
                print(f"{RED}{BOLD}Incorrect fingerprint or password{END}")
                continue
        
            private_key = serialization.load_pem_private_key(
                db_private_key[0].encode('utf-8'),
                password=None
            )   

            rsa = RSA(private_key)

            return rsa

        except mysql.connector.Error as e:
            print(f"MySQL encountered an error: {e}")

def register(connection):
    # User is regestering for the first time, so we create a new key pair
    rsa = RSA()

    print(f"{BOLD}Register a password and you will be provided with a fingerprint.{END}")
    password = input(f"{BOLD}Enter password: {END}")

    fingerprint = base64.b64encode(
        hashlib.sha256(rsa.export_public_key()).digest()
    )
    private_key = rsa.export_private_key()

    query = "INSERT INTO users (fingerprint, password, private_key) VALUES (%s, %s, %s)"
    val = (fingerprint, password, private_key)
    
    cursor = connection.cursor()
    cursor.execute(query, val)
    connection.commit()

    #print(cursor.rowcount, "record(s) inserted")
    print(f"{BOLD}Your fingerprint is:{END} {fingerprint.decode('utf-8')}")

    return rsa

async def send_message_to_recipients(client):
        
    # My fingerprint encoded in base64
    print(f"\n{BOLD}Your fingerprint:{END} {client.encode_fingerprint(client.get_fingerprint())}")
    print(f"\n{BOLD}Available recipients:{END}")

    # print the list of available recipients and their base64 encoded fingerprints
    for fingerprint, info in client.client_list.items():
        encoded_fingerprint = client.encode_fingerprint(fingerprint)
        print(f"{BOLD}Fingerprint:{END} {encoded_fingerprint}")
    
    # ask the user to choose recipients and put the base64 encoded fingerprints in the list
    recipient_encoded_fingerprints = []
    print("")
    while True:
        fingerprint = input(f"{BOLD}Enter recipient fingerprint (or press Enter to finish):{END} ")

        if not fingerprint:
            break

        recipient_encoded_fingerprints.append(fingerprint)
    
    if not recipient_encoded_fingerprints:
        print(f"{YELLOW}No recipients selected. Aborting.{END}")

        return
    
    # get the message from the user
    message = input(f"{BOLD}Enter your message: {END}")
    
    # send the message
    try:
        await client.send_chat(recipient_encoded_fingerprints, message)
        print(f"\n{GREEN}{BOLD}Message sent successfully {END}to {len(recipient_encoded_fingerprints)} recipients!")
    except ValueError as e:
        print(f"\n{RED}{BOLD}Error:{END} {e}")
    except Exception as e:
        print(f"\n{RED}{BOLD}An error occurred:{END} {e}")

def print_commands():
    print(f"\n{BOLD}Available commands:{END}")
    print(f"{BOLD}1. Send chat message{END}")
    print(f"{BOLD}2. Send public chat message{END}")
    print(f"{BOLD}3. Upload file{END}")
    print(f"{BOLD}4. Download file{END}")
    print(f"{BOLD}5. Request and update client list{END}")
    print(f"{BOLD}6. Exit{END}")
    # maybe a command to print out the fingerprints of the most recent client list (so you can list the online users)
    # it would tell the user to request another update if required

async def user_interface(client): 
    """WORKS"""
    while True:
        
        print_commands()

        choice = await asyncio.get_event_loop().run_in_executor(None, input, "Enter your choice (1-6): ")

        if choice == '1':
            await send_message_to_recipients(client)

        elif choice == '2':
            message = await asyncio.get_event_loop().run_in_executor(None, input, f"{BOLD}Enter your public message:{END} ")
            await client.send_public_chat(message)

        elif choice == '3':
            file_path = await asyncio.get_event_loop().run_in_executor(None, input, f"{BOLD}Enter the path of the file to upload:{END} ")
            file_url = await client.upload_file(file_path)

            if file_url:
                print(f"{GREEN}{BOLD}File uploaded successfully. URL:{END} {file_url}")

            else:
                print(f"{RED}{BOLD}File upload failed.{END}")

        elif choice == '4':
            file_url = await asyncio.get_event_loop().run_in_executor(None, input, f"{BOLD}Enter the URL of the file to download:{END} ")
            save_path = await asyncio.get_event_loop().run_in_executor(None, input, f"{BOLD}Enter the path to save the downloaded file:{END} ")
            success = await client.download_file(file_url, save_path)

            if success:
                print(f"{GREEN}{BOLD}File downloaded successfully and saved to{END} {save_path}")

            else:
                print(f"{RED}{BOLD}File download failed.{END}")

        elif choice == '5':
            await client.request_client_list()

            print(f"\n{BOLD}Online recipients:{END}")

            for fingerprint, info in client.client_list.items():
                encoded_fingerprint = client.encode_fingerprint(fingerprint)
                print(f"{BOLD}Fingerprint:{END} {encoded_fingerprint}")

        elif choice == '6':
            print(f"{YELLOW}{BOLD}Exiting...{END}")
            await client.disconnect()
            return

        else:
            print(f"{BOLD}{YELLOW}Invalid choice. Please try again.{END}")
        
        # Small delay to prevent busy-waiting
        await asyncio.sleep(0.1)

async def update_client_list(client, interval = 30):
    while True:
        if client.connected is False:
            return
        
        try:
            await client.request_client_list()

        except Exception as e:
            print(f"{BOLD}{YELLOW}Client list could not be updated{END}")

        await asyncio.sleep(interval)

async def main():
    print(textwrap.dedent('''
      ____  __   ___   ____  _  __    _      __   __                 __                __  ________          __ 
     / __ \/ /  / _ | / __/ / |/ /__ (_)__ _/ /  / /  ___  __ ______/ /  ___  ___  ___/ / / ___/ (_)__ ___  / /_
    / /_/ / /__/ __ |/ _/  /    / -_) / _ `/ _ \/ _ \/ _ \/ // / __/ _ \/ _ \/ _ \/ _  / / /__/ / / -_) _ \/ __/
    \____/____/_/ |_/_/   /_/|_/\__/_/\_, /_//_/_.__/\___/\_,_/_/ /_//_/\___/\___/\_,_/  \___/_/_/\__/_//_/\__/ 
                                     /___/                                                                      
    '''))

    print(textwrap.dedent('''
    Welcome to the OLAF Neighbourhood Client.
    Please login with your fingerprint and password. If you do not have a fingerprint please register instead.
    1. Login
    2. Register
    '''))

    # Initialise database
    connection = manage_db("usersdb")
    rsa_instance = None

    while True:
        choice = input(f"{BOLD}Please select a choice (1-2):{END} ")

        if choice == "1":
            rsa_instance = login(connection)
            break
        
        elif choice == "2":
            rsa_instance = register(connection)
            break

        else:
            print(f"{YELLOW}{BOLD}Invalid choice. Please try again.{END}")

    # Get server address
    print(f"\n{BOLD}To connect to a server you need a IP address and a PORT number.{END}")
    server_ip = input(f"{BOLD}Enter server IP address: {END}")
    server_port = input(f"{BOLD}Enter server PORT number:{END} ")

    server_uri = f"ws://{server_ip}:{server_port}"

    # Create client instance
    client = Client(rsa_instance)

    try:
        await client.connect(server_uri)

        # Client my query the server for a client_list every so often
        
        message_handler = asyncio.create_task(client.handle_messages())
        user_interface_task = asyncio.create_task(user_interface(client))
        keep_alive_task = asyncio.create_task(client.keep_alive())
        update_client_list_task = asyncio.create_task(update_client_list(client, 30))
        
        # Run all tasks concurrently
        await asyncio.gather(message_handler, user_interface_task, keep_alive_task, update_client_list_task)
        
    except ConnectionError:
        print(f"{RED}{BOLD}Failed to establish connection.{END}")

    except asyncio.CancelledError:
        print(f"{RED}{BOLD}Client was cancelled{END}")

    finally:
        if client.websocket:
            await client.disconnect()
            print(f"{BOLD}{RED}Client disconnected{END}")
        
        # Cancel the message handler task if it's still running
        for task in [message_handler, user_interface_task, keep_alive_task, update_client_list_task]:
            if not task.done():
                task.cancel()

                try:
                    await task

                except asyncio.CancelledError:
                    pass

                finally:
                    task = None
        
        # Close MySQL connection
        connection.close()

if __name__ == "__main__":
    asyncio.run(main())