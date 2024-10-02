from cryptography.hazmat.primitives import serialization
from Client import Client
from RSA import RSA
import asyncio
import mysql.connector
import textwrap
import hashlib
import base64

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
        fingerprint = input("Enter your fingerprint: ")
        password = input("Enter your password: ")

        query = f"""SELECT private_key FROM users WHERE fingerprint = '{fingerprint}' AND password = '{password}'"""

        try:
            cursor.execute(query)
            db_private_key = cursor.fetchone()

            if not db_private_key:
                print("Incorrect fingerprint or password")
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

    print("Register a password and you will be provided with a fingerprint.")
    password = input("Enter password: ")

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
    print(f"Your fingerprint is: {fingerprint.decode('utf-8')}")

    return rsa

async def send_message_to_recipients(client):
        
    # My fingerprint encoded in base64
    print(f"\nYour fingerprint: {client.encode_fingerprint(client.get_fingerprint())}")
    print("\nAvailable recipients:")

    # print the list of available recipients and their base64 encoded fingerprints
    for fingerprint, info in client.client_list.items():
        encoded_fingerprint = client.encode_fingerprint(fingerprint)
        print(f"Fingerprint: {encoded_fingerprint}")
    
    # ask the user to choose recipients and put the base64 encoded fingerprints in the list
    recipient_encoded_fingerprints = []
    print("")
    while True:
        fingerprint = input("Enter recipient fingerprint (or press Enter to finish): ")

        if not fingerprint:
            break

        recipient_encoded_fingerprints.append(fingerprint)
    
    if not recipient_encoded_fingerprints:
        print("No recipients selected. Aborting.")

        return
    
    # get the message from the user
    message = input("Enter your message: ")
    
    # send the message
    try:
        await client.send_chat(recipient_encoded_fingerprints, message)
        print(f"\nMessage sent successfully to {len(recipient_encoded_fingerprints)} recipients!")
    except ValueError as e:
        print(f"\nError: {e}")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

def print_commands():
    print("\nAvailable commands:")
    print("1. Send chat message")
    print("2. Send public chat message")
    print("3. Upload file")
    print("4. Download file")
    print("5. Request and update client list")
    print("6. Exit")
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
            message = await asyncio.get_event_loop().run_in_executor(None, input, "Enter your public message: ")
            await client.send_public_chat(message)

        elif choice == '3':
            file_path = await asyncio.get_event_loop().run_in_executor(None, input, "Enter the path of the file to upload: ")
            file_url = await client.upload_file(file_path)

            if file_url:
                print(f"File uploaded successfully. URL: {file_url}")

            else:
                print("File upload failed.")

        elif choice == '4':
            file_url = await asyncio.get_event_loop().run_in_executor(None, input, "Enter the URL of the file to download: ")
            save_path = await asyncio.get_event_loop().run_in_executor(None, input, "Enter the path to save the downloaded file: ")
            success = await client.download_file(file_url, save_path)

            if success:
                print(f"File downloaded successfully and saved to {save_path}")

            else:
                print("File download failed.")

        elif choice == '5':
            await client.request_client_list()

            print("\nOnline recipients:")

            for fingerprint, info in client.client_list.items():
                encoded_fingerprint = client.encode_fingerprint(fingerprint)
                print(f"Fingerprint: {encoded_fingerprint}")

        elif choice == '6':
            print("Exiting...")
            await client.disconnect()
            return

        else:
            print("Invalid choice. Please try again.")
        
        # Small delay to prevent busy-waiting
        await asyncio.sleep(0.1)

async def update_client_list(client, interval = 30):
    while True:
        if client.connected is False:
            return
        
        try:
            await client.request_client_list()

        except Exception as e:
            print("Client list could not be updated")

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
        choice = input("Please select a choice (1-2): ")

        if choice == "1":
            rsa_instance = login(connection)
            break
        
        elif choice == "2":
            rsa_instance = register(connection)
            break

        else:
            print("Invalid choice. Please try again.")

    # Get server address
    print("\nTo connect to a server you need a IP address and a PORT number.")
    server_ip = input("Enter server IP address: ")
    server_port = input("Enter server PORT number: ")

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
        print("Failed to establish connection.")

    except asyncio.CancelledError:
        print("Client was cancelled")

    finally:
        if client.websocket:
            await client.disconnect()
            print("Client disconnected")
        
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