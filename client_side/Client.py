from AES import AES
from RSA import RSA
from client_message_handler import client_message_handler
from websockets.exceptions import WebSocketException
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from urllib.parse import urlparse
import base64
import asyncio
import websockets
import json
import os
import aiohttp
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# def manage_key(pkey = None):
#     # Load keys from file
#     # If the keys don't exist call rsa = RSA() and generate the key pair and export
#     if pkey:
#         print(f"[+] Found public and private RSA keys")

#         private_key = serialization.load_pem_private_key(
#             pkey,
#             password=None
#         )   

#         rsa = RSA(private_key)
        
#     else:
#         print(f"[-] RSA key pair not found")
#         print(f"[*] Generating new RSA key pair")

#         rsa = RSA()

#     return rsa

class Client:
    def __init__(self, rsa):
        self.server_uri = None
        self.rsa = rsa
        self.aes = AES()
        self.cmh = client_message_handler(self.rsa, self.aes)
        self.websocket = None
        self.connected = False # checks if the client is connected to the server
        self.last_counters = {} # identifier of last_counters is each client's fingerprint (bytes)
        self.public_keys = {} # public keys are stored in raw bytes, indexed by fingerprint in raw bytes
        self.client_list = {}
        self.is_shutting_down = False

    async def connect(self, server_uri):
        try:
            self.websocket = await websockets.connect(server_uri)
            self.server_uri = server_uri
            self.connected = True

            print(f"Connected to server: {self.server_uri}")

            await self.send_hello()
            await self.request_client_list()

        except WebSocketException as e:
            print(f"Failed to connect to server: {e}")
            raise ConnectionError(f"Unable to connect to server: {e}")
        
    async def keep_alive(self):
        while self.connected:
            try:
                await self.websocket.ping()
            except Exception as e:
                print(f"Error sending keep-alive ping: {e}")
                await self.handle_disconnect()
                break
            await asyncio.sleep(5)
        
    async def reconnect(self):
        """Attempts to reconnect the client up to a certain amount of times"""
        max_retries = 5
        retry_delay = 5

        for attempt in range(max_retries):
            print(f"Attempting to reconnect (attempt {attempt + 1}/{max_retries})...")
            try:
                await self.connect(self.server_uri)
                return
            except ConnectionError:
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    print("Max reconnection attempts reached. Exiting.")
                    raise

    async def handle_disconnect(self):
        if not self.is_shutting_down:
            self.connected = False
            print("Disconnected from server. Attempting to reconnect...")
            await self.reconnect()
        else:
            print("Client is shutting down. Not attempting to reconnect.")

    async def disconnect(self):
        self.is_shutting_down = True
        self.connected = False
        if self.websocket:
            await self.websocket.close()
        print("Client disconnected")
        
    # functions to handle incoming messages

    async def handle_messages(self):
        while True:
            try:
                message = await self.receive_message()
                if message:
                    # print("\n----------------")
                    # print("message received")
                    # print("----------------\n")
                    await self.process_message(message)
            except ConnectionError:
                await self.handle_disconnect()
                return
            except Exception as e:
                print(f"Error handling incoming message: {e}")

        
    async def receive_message(self):
        if not self.connected:
            raise ConnectionError("Not connected to server")
        try:
            message = await self.websocket.recv()
            return json.loads(message)
        except WebSocketException as e:
            print(f"Error receiving message: {e}")
            await self.handle_disconnect()
            return
        except json.JSONDecodeError as e:
            print(f"Error decoding message: {e}")
            return None
        
    async def process_message(self, message):
        """Processes the two different types of messages
        and performs checks on them to see if the message
        is meant for this client"""
        try:
            if message["type"] == "signed_data":
                fingerprint = self.extract_fingerprint(message) # returns fingerprint in raw bytes
                if fingerprint == None:
                    return
                # print(f"decoded fingerprint: {fingerprint}")
                # print(f"encoded fingerprint: {self.encode_fingerprint(fingerprint)}")
                if fingerprint:
                    data_to_verify = json.dumps(message['data']) + str(message['counter'])
                    # print(f"data to verify: {data_to_verify.encode('utf-8')}")
                    signature = base64.b64decode(message["signature"]) # returns signature in raw bytes
                    # print(f"signature to verify: {signature}")
                    sender_public_key = self.client_list[fingerprint]["public_key"] # gets public key in bytes
                    # print(f"sender public key: {sender_public_key}")
                    # print(f"my public key: {self.rsa.export_public_key()}")
                    if self.rsa.verify(serialization.load_pem_public_key(sender_public_key), data_to_verify.encode('utf-8'), signature):
                        if self.check_counter(message, fingerprint):
                            await self.process_signed_data(message['data'])
                            if fingerprint != self.get_fingerprint():
                                print_commands()
                    else:
                        print(f"Invalid signature for message from {self.encode_fingerprint(fingerprint)}")
                else:
                    print("Could not extract fingerprint from message")
            elif message["type"] == "client_list":
                self.update_client_list(message["servers"])
                # logging.info(f"Received and updated client list")
            else:
                print(f"Unknown message type: {message['type']}")
        except KeyError as e:
            print(f"Invalid message format: {e}")
        except Exception as e:
            print(f"Error processing message: {e}")


    async def process_signed_data(self, data):
        try:
            # if data["type"] == "hello":
            #     await self.handle_hello(data)
            if data["type"] == "chat":
                await self.process_chat(data)
            elif data["type"] == "public_chat":
                await self.handle_public_chat(data)
            else: 
                print(f"Unknown inner message type: {data['type']}")
        except KeyError as e:
            print(f"Invalid inner message format: {e}")
        except Exception as e:
            print(f"Error processing inner message: {e}")

    def get_fingerprint(self, public_key=None):
        """Takes the public key and generates fingerprint for it
        If called with no argument, retrives current client's fingerprint
        Returns fingerprint in bytes, takes public key argument in bytes"""
        try:
            if public_key is None:
                public_key = self.rsa.export_public_key()
            digest = hashes.Hash(hashes.SHA256())
            digest.update(public_key)
            return digest.finalize() # returns fingerprint in raw bytes
        except Exception as e:
            print(f"Error generating fingerprint: {e}")
            return None
        
    def encode_fingerprint(self, fingerprint: bytes) -> str:
        """Encodes a fingerprint that is in raw bytes to its base64 string represenation"""
        return base64.b64encode(fingerprint).decode('utf-8')

    def decode_fingerprint(self, encoded_fingerprint: str) -> bytes:
        """Decodes a fingerprint that is in its base64 string represenation to raw bytes"""
        return base64.b64decode(encoded_fingerprint.encode('utf-8'))

    # async def handle_hello(self, data):
    #     try:
    #         public_key = base64.b64decode(data["public_key"]) # returns public_key in raw bytes
    #         fingerprint = self.get_fingerprint(public_key) # gets fingerprint in raw bytes
    #         self.public_keys[fingerprint] = public_key
    #         print(f"Received hello from {fingerprint}")
    #     except Exception as e:
    #         print(f"Error handling hello message: {e}")
    
    async def process_chat(self, data):
        try:
            iv = base64.b64decode(data['iv'])
            encrypted_chat = base64.b64decode(data['chat'])
            encrypted_symm_keys = data["symm_keys"] 

            client_public_key = base64.b64encode(self.rsa.export_public_key()).decode('utf-8')
            if client_public_key not in encrypted_symm_keys:
                print("Received chat message not intended for this client")
                return
            encrypted_symm_key = base64.b64decode(encrypted_symm_keys[client_public_key])
                
            symm_key = self.rsa.decrypt(encrypted_symm_key)
            temp_aes = AES()
            temp_aes.key = symm_key
                
            decrypted_chat = temp_aes.decrypt(iv, encrypted_chat)
            chat_data = json.loads(decrypted_chat.decode('utf-8'))
           
            sender = chat_data["participants"][0]
            print(f"Chat from {sender}: {chat_data['message']}")
        except KeyError as e:
            print(f"Invalid chat message format: {e}")
        except ValueError as e:
            print(f"Error decoding base64 data: {e}")
        except InvalidSignature:
            print("Invalid signature in chat message")
        except Exception as e:
            print(f"Error processing chat message: {e}")
    
    async def handle_public_chat(self, data):
        """Handles the public chat sent by another user (*WORKS*)"""
        try:
            sender = data["sender"]
            message = data["message"]
            print(f"Public chat from {sender}: {message}")
        except KeyError as e:
            print(f"Invalid public chat message format: {e}")
        except Exception as e:
            print(f"Error handling public chat message: {e}")
    
    def update_client_list(self, servers):
        """WORKS"""
        self.client_list.clear()
        for server in servers:
            for public_key in server['clients']:
                fingerprint = self.get_fingerprint(public_key.encode('utf-8')) # gets the fingerprint as raw bytes
                self.client_list[fingerprint] = {
                    "public_key": public_key.encode('utf-8'), # public key is stored in bytes
                    "server": server['address']
                }
                # print(public_key.encode('utf-8'))
    
    def extract_fingerprint(self, message):
        """Extracts the fingerprint of the message received and
        returns it in its raw bytes form
        Confirmed that extracting fingerprint for public chat works"""
        data = message['data']
        
        if data['type'] == 'hello':
            public_key = base64.b64decode(data['public_key']) # returns the public key in bytes
            fingerprint = self.get_fingerprint(public_key) # returns fingerprint in raw bytes
            self.public_keys[fingerprint] = public_key
            return fingerprint
        
        elif data['type'] == 'chat':
            try:
                iv = base64.b64decode(data['iv'])
                encrypted_chat = base64.b64decode(data['chat'])
                encrypted_symm_keys = data["symm_keys"] 

                client_public_key = base64.b64encode(self.rsa.export_public_key()).decode('utf-8')
                if client_public_key not in encrypted_symm_keys:
                    print("Received chat message not intended for this client")
                    return None
                encrypted_symm_key = base64.b64decode(encrypted_symm_keys[client_public_key])
                # print(f"encrypted key:{encrypted_symm_key}")
                symm_key = self.rsa.decrypt(encrypted_symm_key)
                decrypted_chat = self.aes.decrypt(iv, encrypted_chat, symm_key)
                chat_data = json.loads(decrypted_chat.decode('utf-8'))
                # print(chat_data)

                return self.decode_fingerprint(chat_data['participants'][0])
            except Exception as e:
                print(f"Error decrypting chat message (extract): {e}")
                return None
        
        elif data['type'] == 'public_chat':
            return self.decode_fingerprint(data['sender']) # decodes fingerprint to raw bytes
        
        else:
            print(f"Unknown data type: {data['type']}")
            return None
        
        
    def check_counter(self, signed_data, fingerprint):
        """Checks for replay attack by comparing the counter to the last
        stored value of the counter. Uses the fingerprint in byte form as the 
        index of the last_counter set"""
        current_counter = signed_data['counter']
        # finds the last counter stored, the 0 argument is the default value
        last_counter = self.last_counters.get(fingerprint, 0)
        encoded_fingerprint = self.encode_fingerprint(fingerprint)
        
        if current_counter <= last_counter:
            # print(f"counter invalid: counter for fingerprint {encoded_fingerprint} is {current_counter}, last stored counter is {last_counter}")
            return False
        
        # uses the fingerprint provided in byte form to update the latest counter
        self.last_counters[fingerprint] = current_counter
        # print(f"counter valid: counter for fingerprint {encoded_fingerprint} updated to {current_counter}")
        return True
    

    # functions to send outgoing messages
    # all fingerprints are sent to the server and to other clients as base64 encoded string

    async def send_hello(self):
        """WORKS"""
        try:
            hello_message = self.cmh.hello()
            await self.send_message(hello_message)
        except Exception as e:
            print(f"Error sending hello message: {e}")

    async def send_chat(self, recipient_encoded_fingerprints: list[str], message: str):
        try:
            recipient_fingerprints = [base64.b64decode(f) for f in recipient_encoded_fingerprints]
            
            destination_servers = []
            recipient_rsa_pub_keys = [] 
            
            for fingerprint in recipient_fingerprints:
                if fingerprint not in self.client_list:
                    raise ValueError(f"Recipient with fingerprint {self.encode_fingerprint(fingerprint)} not found in client list")
                
                recipient_info = self.client_list[fingerprint]
                destination_servers.append(recipient_info['server'])
                recipient_rsa_pub_keys.append(recipient_info['public_key'])

            # Encode our own fingerprint
            sender_fingerprint = self.get_fingerprint()

            chat_message = self.cmh.chat(
                sender_fingerprint=sender_fingerprint,
                participant_fingerprints=recipient_fingerprints,
                message=message,
                destination_servers=destination_servers,
                recipient_rsa_pub_keys=recipient_rsa_pub_keys
            )
            await self.send_message(chat_message)
            #print(f"Chat message sent to {len(recipient_encoded_fingerprints)} recipients")
        except Exception as e:
            print(f"Error sending chat message: {e}")

    async def send_public_chat(self, message):
        """WORKS"""
        try:
            public_chat_message = self.cmh.public_chat(
                sender_fingerprint=self.encode_fingerprint(self.get_fingerprint()),
                message=message
            )
            await self.send_message(public_chat_message)
        except Exception as e:
            print(f"Error sending public chat message: {e}")

    async def request_client_list(self):
        """WORKS"""
        try:
            client_list_request = {
                "type": "client_list_request"
            }
            await self.send_message(client_list_request)
            # logging.info("Client list requested")
        except Exception as e:
            print(f"Error requesting client list: {e}")

    async def send_message(self, message):
        """WORKS"""
        if not self.connected:
            raise ConnectionError("Not connected to server")
        try:
            await self.websocket.send(json.dumps(message))
        except WebSocketException as e:
            print(f"Error sending message: {e}")
            self.connected = False
            await self.reconnect()

    # async def send_message_to_recipients(self):
        
    #     # My fingerprint encoded in base64
    #     print(f"Your fingerprint: {self.encode_fingerprint(self.get_fingerprint())}")
        
    #     # print the list of available recipients and their base64 encoded fingerprints
    #     print("Available recipients:")
    #     for fingerprint, info in self.client_list.items():
    #         encoded_fingerprint = self.encode_fingerprint(fingerprint)
    #         print(f"Fingerprint: {encoded_fingerprint}")
        
    #     # ask the user to choose recipients and put the base64 encoded fingerprints in the list
    #     recipient_encoded_fingerprints = []
    #     while True:
    #         fingerprint = input("Enter recipient fingerprint (or press Enter to finish): ")
    #         if not fingerprint:
    #             break
    #         recipient_encoded_fingerprints.append(fingerprint)
        
    #     if not recipient_encoded_fingerprints:
    #         print("No recipients selected. Aborting.")
    #         return
        
    #     # get the message from the user
    #     message = input("Enter your message: ")
        
    #     # send the message
    #     try:
    #         await self.send_chat(recipient_encoded_fingerprints, message)
    #         print(f"Message sent successfully to {len(recipient_encoded_fingerprints)} recipients!")
    #     except ValueError as e:
    #         print(f"Error: {e}")
    #     except Exception as e:
    #         print(f"An error occurred: {e}")

    # functions for file transfer
    """WORKS"""

    async def upload_file(self, file_path: str) -> Optional[str]:

        if not self.connected:
            raise ConnectionError("Not connected to server")

        try:
            async with aiohttp.ClientSession() as session:
                file_name = os.path.basename(file_path)
                with open(file_path, 'rb') as f:
                    form_data = aiohttp.FormData()
                    form_data.add_field('file', f, filename=file_name)

                    parsed_uri = urlparse(self.server_uri)
                    ip = parsed_uri.hostname
                    port = parsed_uri.port
                    
                    async with session.post(f"http://{ip}:{port + 1}/api/upload", data=form_data) as response:
                        if response.status == 200:
                            json_response = await response.json()
                            return json_response.get('file_url')
                        elif response.status == 413:
                            logging.error("File upload rejected: File too large")
                        else:
                            logging.error(f"File upload failed with status code: {response.status}")
        except Exception as e:
            logging.error(f"Error uploading file: {e}")
        
        return None

    async def download_file(self, file_url: str, save_path: str) -> bool:

        if not self.connected:
            raise ConnectionError("Not connected to server")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(file_url) as response:
                    if response.status == 200:
                        with open(save_path, 'wb') as f:
                            while True:
                                chunk = await response.content.read(8192)  # Read in 8K chunks
                                if not chunk:
                                    break
                                f.write(chunk)
                        logging.info(f"File downloaded successfully and saved to {save_path}")
                        return True
                    else:
                        logging.error(f"File download failed with status code: {response.status}")
        except Exception as e:
            logging.error(f"Error downloading file: {e}")
        
        return False
    
def print_commands():
    print("\nAvailable commands:")
    print("1. Send chat message")
    print("2. Send public chat message")
    print("3. Upload file")
    print("4. Download file")
    print("5. Request and update client list")
    print("6. Exit")

# async def user_interface(client): 
#     """WORKS"""
#     while True:
        
#         print_commands()

#         choice = await asyncio.get_event_loop().run_in_executor(None, input, "Enter your choice (1-6): ")
#         if choice == '1':
#             await client.send_message_to_recipients()
#         elif choice == '2':
#             message = await asyncio.get_event_loop().run_in_executor(None, input, "Enter your public message: ")
#             await client.send_public_chat(message)
#         elif choice == '3':
#             file_path = await asyncio.get_event_loop().run_in_executor(None, input, "Enter the path of the file to upload: ")
#             file_url = await client.upload_file(file_path)
#             if file_url:
#                 print(f"File uploaded successfully. URL: {file_url}")
#             else:
#                 print("File upload failed.")
#         elif choice == '4':
#             file_url = await asyncio.get_event_loop().run_in_executor(None, input, "Enter the URL of the file to download: ")
#             save_path = await asyncio.get_event_loop().run_in_executor(None, input, "Enter the path to save the downloaded file: ")
#             success = await client.download_file(file_url, save_path)
#             if success:
#                 print(f"File downloaded successfully and saved to {save_path}")
#             else:
#                 print("File download failed.")
#         elif choice == '5':
#             await client.request_client_list()
#             print("Available recipients:")
#             for fingerprint, info in client.client_list.items():
#                 encoded_fingerprint = client.encode_fingerprint(fingerprint)
#                 print(f"Fingerprint: {encoded_fingerprint}")
#         elif choice == '6':
#             print("Exiting...")
#             await client.disconnect()
#             break
#         else:
#             print("Invalid choice. Please try again.")
        
#         # Small delay to prevent busy-waiting
#         await asyncio.sleep(0.1)

# async def main():
#     private_key = b"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClYsPPGtk9G0Ng\ngOmzXLzkCTrEIgvRjV7BD+xEVM+koQtbez6z4pF9iloyrPAm6gNXlqu1ZV4zxbg7\n+KZT3P/N9JEqn7H02ij1Jf+koHgvQzila+i6WFqnFyp3U2tvw63WppKUgazbHZSg\nguHygIogd3AM/104yecrzUtU0SmjMshc1uWru1v20i8tiUtsDzxZBEZN6jWhK18O\ngaURQIDYHdDCGl0PFpvVf51jjY1W7tNb13v6q1Zbx9kccsP+M4ntUtksleWG2asC\n/VuoNBMPixh/x4FZcDr7U6mXNuq4hJONGFuI7fDf1Us1Cs8lxJaTaKhRQhEY+RhZ\ngKJ+aH83AgMBAAECggEAUIHr/KC+uFrRqSQH34qY3s7JXxmNtEQDqKqWIktAywyk\nKTOs+cckeL7FGp8Jxn+rAdO0IXjHax9oCDWJzhAqK/lOQzf62kzqnC+TqvF8n9Ey\nvX/yieehtW32+6BNj9nrAS8T8pvPZ9iV9a7Qy4ob8yMBFiqnGBJc6HsmnRK2mJzC\nPoiHctka7qaZC906TZElvKgS8lf2w+Bp/LeWSxLBO0xsk3VBZqulvFHbl8yGTjqE\nh6LdKzBYjrHSxDK2XcqREzhd8uJCPZ1nQU6fklL5XWiy55APGUiOfuC6fhPbSEzz\nXfNVqKxk2BoAWUcKZ3I471WQkHlimyhb7SVsQY4RAQKBgQC8G9OLnQsYrM2QO38I\nvaTsfrn5kYv67Lw1fnyPgsrZ9dGmDC18k3bAAc/wl6/InR0lwHCYxgGI3ZbFaASg\nXCPnuraIHE6mLbTvr4vgxjwOauT6qnHlnBsv4Aj99f3Q2fiGY3rwJEMHyAAmivV/\nWoMUmh9EibOnajmgm6pAM3B/AQKBgQDhE3jet/OqfVFv9m5nfbkrdZnYZNy3xGOw\nQH0rhaoV0EPtPor71r7l5NJadMrC/6IYWNcG2ZLZzl5zl8FJu6z3TX40G/8RCDhC\noe1pG+SX67ujvT7MLSnn3R7WgYcWeUXLx7cLceAcy27cJzm1ikLGyn8BhRL6550L\n0x+dqXM2NwKBgDRfrwO1Quyo2EcrOZBudOff1Nn2uzmvBiwCvp2ade4/shKAW33O\n9QY6uvGq2ieKDx5+uRrgLncz8xGdh4Q6g0i2xLGa6A7+tNzzTIfVyczd2Ekuga3D\nTBKFVxuWjQfEWJzaP9Vy0zLsbZZNpFLEGbD3xHLpwBqBye+8x6c+azkBAoGAcx9T\nlo9+WXjJ27uvUs3ylXEMZKuKXZBc8Py7STSP/6JL7CAuVIvNjqcQlOXiBAVe8pcW\nPNGylCdDFlrLqZwN51xCrgKX3y1WIXbTiQyUSsRvcFvOr/51zbvDFzKfVvZmpcmc\nLYVsfS3soTyK/vkeGLHgbnWTdLRdFnxBUpImdNcCgYB+9wugTKNVjYf0rqyPNUrr\nA835zPwGmegSr3w/oyjS9oESmxrRryvicAK0uItgpi6CLt8Ger13cCdDRfx4SHod\nmtFCCMj5D2phEFX4lhuLZgncM8y8UFLQP/VtrbSOJCLU5La/+Yxsz095/JlcerGN\nm0fMyhfS2laPIDS4Lcphxg==\n-----END PRIVATE KEY-----\n"
#     uri = "ws://127.0.0.1:8888"
#     # rsa = manage_key(private_key)
#     rsa = manage_key() # for testing
#     client = Client(rsa)
#     # print(client.rsa.export_private_key())
#     print("Starting Client")
    
#     try:
#         await client.connect(uri)
        
#         message_handler = asyncio.create_task(client.handle_messages())
#         user_interface_task = asyncio.create_task(user_interface(client))
#         keep_alive_task = asyncio.create_task(client.keep_alive())
        
#         # Run all tasks concurrently
#         await asyncio.gather(message_handler, user_interface_task, keep_alive_task)
        
#     except ConnectionError:
#         logging.error("Failed to establish connection.")
#     except asyncio.CancelledError:
#         logging.info("Client was cancelled")
#     finally:
#         if not client.is_shutting_down:
#             await client.disconnect()  # Ensure disconnect is called if not already done
        
#         # Cancel the message handler task if it's still running
#         for task in [message_handler, user_interface_task, keep_alive_task]:
#             if not task.done():
#                 task.cancel()
#                 try:
#                     await task
#                 except asyncio.CancelledError:
#                     pass

# if __name__ == "__main__":
#     asyncio.run(main())
