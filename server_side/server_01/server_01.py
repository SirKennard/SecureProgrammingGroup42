from handlers.format_message import format_message
from utils.init_keys import init_keys
from cryptography.hazmat.primitives import serialization
from aiohttp import web
import asyncio
import websockets
import logging
import json
import base64
import os
import uuid 

current_dir = os.path.dirname(__file__)

CLIENT_LIST_FILE = os.path.join(current_dir, "local", "client_list.json")
SERVER_NEIGHBOURHOOD_FILE = os.path.join(current_dir, "local", "server_neighbourhood.json")
PRIVATE_KEY_FILE = os.path.join(current_dir, "local", "server_private_key.pem")
PUBLIC_KEY_FILE = os.path.join(current_dir, "local", "server_public_key.pem")
LOG_FILE = os.path.join(current_dir, "local", "server.log")

HOST = "127.0.0.1"
PORT = 4444

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("WebSocketServer")

class HTTPServer:
    def __init__(self):
        self.max_file_size = 5 * 1024 * 1024 # 5 Megabytes
        os.makedirs('uploads', exist_ok=True)
        self.app = web.Application()
        self.app.add_routes([web.post('/api/upload', self.handle_file_post)])
        self.app.add_routes([web.get('/uploads/{filename}', self.handle_file_get)])

    async def handle_file_post(self, reqest):
        reader = await reqest.multipart()
        field = await reader.next()

        if field.name == "file":
            filename = field.filename
            file_path = os.path.join('uploads', f'{uuid.uuid4()}_{filename}')
            total_size = 0

            with open(file_path, 'wb') as file:
                while True:
                    chunk = await field.read_chunk()

                    if not chunk:
                        break
                        
                    total_size += len(chunk)

                    if total_size > self.max_file_size:
                        return web.Response(status=413, text="File size exceeds 5MB limit")
                    
                    file.write(chunk)

            file_url = f"http://{HOST}:{PORT + 1}/uploads/{os.path.basename(file_path)}"

            return web.json_response({'file_url':file_url})
        
        return web.Response(status=400, text="Invalid request")

    async def handle_file_get(self, request):
        filename = request.match_info['filename']
        file_path = os.path.join('uploads', filename)

        if os.path.exists(file_path):
            return web.FileResponse(file_path)
        
        return web.Response(status=404, text="File not found")
    
    async def serve(self):
        runner = web.AppRunner(self.app)
        await runner.setup()

        site = web.TCPSite(runner, HOST, PORT + 1)
        await site.start()

        logging.info(f"[*] HTTP server running on http://{HOST}:{PORT + 1}")

class WebSocketServer:
    def __init__(self, rsa, format_message):
        self.rsa = rsa
        self.format_m = format_message
        self.connected_clients = set()
        self.connected_servers = {}

    async def connect_to_server(self, uri):
        try:
            websocket = await websockets.connect(uri)
            logger.info(f"[*] Connecting to server {uri}")
            self.connected_servers[uri] = websocket

            # Handle recieved messages concurently
            asyncio.create_task(self.recieve_from_server(websocket))
           
            return websocket
            
        except (ConnectionRefusedError, websockets.exceptions.InvalidStatusCode) as e:
            logger.error(f"[#] Could not connect to {uri}")

            return None

    async def recieve_from_server(self, ws):
        try:
            await self.websocket_handler(ws)

        except websockets.exceptions.ConnectionClosed:
            logger.warning(f"[-] Connection to {ws.remote_address} closed.")

        except Exception as e:
            logger.error(f"[#] Could not recieve message from {ws.remote_address}: {e}")

    async def send_to_server(self, ws, data):
        ip, port = ws.remote_address
        logger.info(f"[+] Sending to {ip}:{port}")
        await ws.send(data)

    async def send_server_hello(self):
        # Read the server list file assume it always exists
        with open(SERVER_NEIGHBOURHOOD_FILE, 'r') as file:
            data = json.load(file)

        server_uri = [server["uri"] for server in data.get("servers", []) if f"ws://{HOST}:{PORT}" != server["uri"]]
        message = json.dumps(self.format_m.server_hello(HOST, PORT))
        tasks = []

        for uri in server_uri:
            ws = await self.connect_to_server(uri)  # Create WebSocket connection

            if ws:
                task = asyncio.create_task(self.send_to_server(ws, message))
                tasks.append(task)

        # Wait for all tasks to complete concurrently
        await asyncio.gather(*tasks)

    async def send_client_update_request(self):
        # Read the server list file assume it always exists
        with open(SERVER_NEIGHBOURHOOD_FILE, 'r') as file:
            data = json.load(file)

        # Send a client_update_request to all servers
        message = json.dumps(self.format_m.client_update_request())
        
        server_uri = [server["uri"] for server in data.get("servers", []) if f"ws://{HOST}:{PORT}" != server["uri"]]
        tasks = []
        ws = None
       
        for uri in server_uri:
            try:
                ws = self.connected_servers[uri]
            
            except:
                logger.error(f"[#] Could not connect to {uri}")

            if ws:
                task = asyncio.create_task(self.send_to_server(ws, message))
                tasks.append(task)

        # Wait for all tasks to complete concurrently
        await asyncio.gather(*tasks)

    async def handle_hello(self, client_public_key):
        # Send a client_update message to all other servers in the neighbourhood
        try:
            with open(CLIENT_LIST_FILE, 'r') as file:
                data = json.load(file)

        except FileNotFoundError:
            # If the file doesn't exist, start with an empty structure
            data = {
                "servers": [
                    {
                        "address": f"ws://{HOST}:{PORT}",
                        "clients": []
                    }
                ]
            }

        # Cleck for duplicate client entries
        duplicate = False
        current_server = data['servers'][0] 

        for client in current_server['clients']:
            if client == client_public_key:
                logger.info(f"[+] Client already in list. Aborting operation")
                duplicate = True

        # Create the new entry and append it to the client_list file
        if not duplicate:
            current_server['clients'].append(client_public_key)
            
            with open(CLIENT_LIST_FILE, 'w') as file:
                json.dump(data, file, indent=4)

        # Read the server list file assume it always exists
        with open(SERVER_NEIGHBOURHOOD_FILE, 'r') as file:
            data = json.load(file)
        
        # Read the client list and send a client_update to all servers
        with open(CLIENT_LIST_FILE, 'r') as file:
            client_list = json.load(file)

        message = json.dumps(self.format_m.client_update(client_list['servers'][0]['clients']))
        
        server_uri = [server["uri"] for server in data.get("servers", []) if f"ws://{HOST}:{PORT}" != server["uri"]]
        tasks = []
        ws = None
        
        for uri in server_uri:
            try:
                ws = self.connected_servers[uri]
            
            except:
                logger.error(f"[#] Could not connect to {uri}")

            if ws:
                task = asyncio.create_task(self.send_to_server(ws, message))
                tasks.append(task)

        # Wait for all tasks to complete concurrently
        await asyncio.gather(*tasks)

    async def handle_server_hello(self, ws, b64signiture, data, counter):
        # Verify the connecting server
        message = (json.dumps(data) + str(counter)).encode()
        server_uri = f"ws://{data['sender']}"
        self.connected_servers[server_uri] = ws

        # Read the server list file assume it always exists
        with open(SERVER_NEIGHBOURHOOD_FILE, 'r') as file:
            data = json.load(file)

        pub_key = [server["public_key"].encode() for server in data.get("servers", []) if server_uri == server["uri"]]
        signiture = base64.b64decode(b64signiture)

        if not self.rsa.verify(serialization.load_pem_public_key(pub_key[0]), message, signiture):
            logger.warning(f"[-] Server {server_uri} could not be verified, closing connection")
            await ws.close()

        else:
            logger.info(f"[+] Server {server_uri} was verified successfully")

    async def handle_client_list_request(self, ws):
        # Respond with the client list of all servers
        try:
            with open(CLIENT_LIST_FILE, 'r') as file:
                data = json.load(file)

        except FileNotFoundError:
            # If the file doesn't exist, start with an empty structure
            data = {
                "servers": [
                    {
                        "address": f"ws://{HOST}:{PORT}",
                        "clients": []
                    }
                ]
            }

        for server in data['servers']:
            server['address'] = server['address'][5:] if server['address'].startswith('ws://') else server['address']

        ip, port = ws.remote_address
        message = json.dumps(self.format_m.client_list(data['servers']))

        if ws in self.connected_clients:
            logger.info(f"[+] Sending to {ip}:{port}")
            await ws.send(message)

    async def handle_client_update_request(self, ws):
        # Respond with client_update
        # Send a client_update to the server requesting
        # Read the client list and send a client_update to all servers
        try:
            with open(CLIENT_LIST_FILE, 'r') as file:
                data = json.load(file)

        except FileNotFoundError:
            # If the file doesn't exist, start with an empty structure
            data = {
                "servers": [
                    {
                        "address": f"ws://{HOST}:{PORT}",
                        "clients": []
                    }
                ]
            }

        server_address = f"ws://{HOST}:{PORT}"
        current_server = next((server for server in data['servers'] if server['address'] == server_address), None)

        if current_server:
            clients_list = current_server['clients']

        else:
            # If no current server entry exists, use an empty list
            clients_list = []

        message = json.dumps(self.format_m.client_update(clients_list))

        await self.send_to_server(ws, message)

    async def handle_client_update(self, ws, json_message):
        # Update the client update list
        new_client_list = json_message["clients"]

        # Send a client_update message to all other servers in the neighbourhood
        try:
            with open(CLIENT_LIST_FILE, 'r') as file:
                data = json.load(file)

        except FileNotFoundError:
            # If the file doesn't exist, start with an empty structure
            data = {
                "servers": [
                    {
                        "address": f"ws://{HOST}:{PORT}",
                        "clients": []
                    }
                ]
            }

        server_address = None

        for uri, websocket in self.connected_servers.items():
            if websocket == ws:
               server_address = uri

        current_server = next((server for server in data['servers'] if server['address'] == server_address), None)
        
        if current_server is None:
            # If the current server is not in the list, add it
            current_server = {
                "address": server_address,
                "clients": []
            }

            data['servers'].append(current_server)

        current_client_list = current_server["clients"]

        # Add new clients if they don't already exist in the list
        for client in new_client_list:
            if client not in current_client_list:
                current_client_list.append(client)

        # Update the client list for the current server
        current_server["clients"] = current_client_list

        # Write the updated data back to the file
        with open(CLIENT_LIST_FILE, 'w') as file:
            json.dump(data, file, indent=4)   

    async def handle_public_chat(self, ws, json_message):
        if self.connected_clients:
            logger.info(f"[+] Broadcasting to {len(self.connected_clients)} connections")

        for client in self.connected_clients:
            await client.send(json.dumps(json_message))

        with open(SERVER_NEIGHBOURHOOD_FILE, 'r') as file:
            data = json.load(file)

        if ws in self.connected_clients:
            # Send a client_update_request to all servers
            message = json.dumps(json_message)
            
            server_uri = [server["uri"] for server in data.get("servers", []) if f"ws://{HOST}:{PORT}" != server["uri"]]
            tasks = []
            ws = None
        
            for uri in server_uri:
                try:
                    ws = self.connected_servers[uri]
                
                except:
                    logger.error(f"[#] Could not connect to {uri}")

                if ws:
                    task = asyncio.create_task(self.send_to_server(ws, message))
                    tasks.append(task)

            # Wait for all tasks to complete concurrently
            await asyncio.gather(*tasks)

    async def handle_chat(self, ws, json_message):
        # If the chat message was sent by one of the clients then relay
        if ws in self.connected_clients:
            server_uri = [f"ws://{server}" for server in json_message["data"]["destination_servers"]]
            tasks = []
            ws = None

            for uri in server_uri:
                # If this server is a destination server then flood to all its clients
                if uri == f"ws://{HOST}:{PORT}":
                    for client in self.connected_clients:
                        await client.send(json.dumps(json_message))

                # Otherwise relay message to appropriate server
                else:
                    try:
                        ws = self.connected_servers[uri]
                
                    except:
                        logger.error(f"[#] Could not connect to {uri}")

                    if ws:
                        task = asyncio.create_task(self.send_to_server(ws, json.dumps(json_message)))
                        tasks.append(task)

            await asyncio.gather(*tasks)

        # Otherwise the chat message was sent by a server, flood connected clients
        else:
            for client in self.connected_clients:
                await client.send(json.dumps(json_message))

    async def handle_client_disconnect(self, client_public_key):
        try:
            # Open the client list file
            with open(CLIENT_LIST_FILE, 'r') as file:
                data = json.load(file)

            current_server = data['servers'][0]  # Assuming the first server is the current one

            # Check if the client exists in the current server's client list
            if client_public_key in current_server['clients']:
                # Remove the client from the list
                current_server['clients'].remove(client_public_key)

                # Write the updated client list back to the file
                with open(CLIENT_LIST_FILE, 'w') as file:
                    json.dump(data, file, indent=4)

                logger.info(f"[+] Client removed from the list")

            else:
                logger.warning(f"[-] Client not found in the list")

        except FileNotFoundError:
            # If the file doesn't exist, log the error
            logger.error(f"[#] Client list file {CLIENT_LIST_FILE} not found")

        except Exception as e:
            logger.error(f"[#] Error occurred while removing client: {e}")

    async def websocket_handler(self, websocket):
        CLIENT_IP, CLIENT_PORT = websocket.remote_address
        prev_counter = 0
        client_public_key = b""

        logger.info(f"[+] {CLIENT_IP}:{CLIENT_PORT} connected")
        
        try:
            async for message in websocket:
                if not message:  # Check if the message is empty
                    logger.warning(f"[-] Empty message received from {CLIENT_IP}:{CLIENT_PORT}")
                    await websocket.close(code=4004, reason="Empty message received")
                    break

                json_message = None

                # If the recieved message is not able to be decoded then close the connection
                try:
                    json_message = json.loads(message)

                except json.JSONDecodeError as e:
                    logger.error(f"[#] Could not decode message from {CLIENT_IP}:{CLIENT_PORT}: {e}")
                    await websocket.close(code=4000, reason="Invalid JSON format")
                    break

                logger.info(f"[+] Recieved\n{json.dumps(json_message, indent=4)}\nfrom {CLIENT_IP}:{CLIENT_PORT}")

                # Message handler
                if json_message['type'] == 'signed_data':
                    # Check if the counter is different
                    if not prev_counter == json_message['counter']:
                        # Update the counter
                        prev_counter = json_message['counter']

                        if json_message['data']['type'] == 'hello':
                            logger.info(f"[+] Recieved hello from {CLIENT_IP}:{CLIENT_PORT}")
                            client_public_key = json_message['data']['public_key']
                            self.connected_clients.add(websocket)

                            await self.handle_hello(client_public_key)

                        elif json_message['data']['type'] == 'server_hello':
                            logger.info(f"[+] Recieved server_hello from {CLIENT_IP}:{CLIENT_PORT}")
                            await self.handle_server_hello(websocket, json_message['signature'], json_message['data'], json_message['counter'])

                        elif json_message['data']['type'] == 'public_chat':
                            logger.info(f"[+] Recieved public_chat from {CLIENT_IP}:{CLIENT_PORT}")
                            await self.handle_public_chat(websocket, json_message)

                        elif json_message['data']['type'] == 'chat':
                            logger.info(f"[+] Recieved chat from {CLIENT_IP}:{CLIENT_PORT}")
                            await self.handle_chat(websocket, json_message)

                        else:
                            logger.warning(f"[-] Unknown signed_data type from {CLIENT_IP}:{CLIENT_PORT}, closing connection")
                            await websocket.close(code=4001, reason="Unknown signed_data type")
                            break
                    else:
                        logger.warning(f"[-] Duplicate counter detected from {CLIENT_IP}:{CLIENT_PORT}")
                        await websocket.close(code=4002, reason="Duplicate counter")
                        break

                elif json_message['type'] == 'client_list_request':
                    logger.info(f"[+] Recieved client_list_request from {CLIENT_IP}:{CLIENT_PORT}")
                    await self.handle_client_list_request(websocket)

                elif json_message['type'] == 'client_update_request':
                    logger.info(f"[+] Recieved client_update_request from {CLIENT_IP}:{CLIENT_PORT}")
                    await self.handle_client_update_request(websocket)

                elif json_message['type'] == 'client_update':
                    logger.info(f"[+] Recieved client_update from {CLIENT_IP}:{CLIENT_PORT}")
                    await self.handle_client_update(websocket, json_message)

                else:
                    logger.warning(f"[-] Unknown message type from {CLIENT_IP}:{CLIENT_PORT}, closing connection")
                    await websocket.close(code=4003, reason="Unknown message type")
                    break

        except websockets.ConnectionClosedOK as e:
            # Graceful close handling (client closed connection properly)
            logger.info(f"[+] {CLIENT_IP}:{CLIENT_PORT} disconnected: {e}")

        except websockets.ConnectionClosedError as e:
            # Error during connection (client disconnected abruptly)
            logger.warning(f"[-] {CLIENT_IP}:{CLIENT_PORT} disconnected with error: {e}")

        except Exception as e:
            logger.error(f"[#] Error handling message from {CLIENT_IP}:{CLIENT_PORT}: {e}")

        finally:
            if not websocket.closed:
                await websocket.close()

            logger.info(f"[+] {CLIENT_IP}:{CLIENT_PORT} disconnected, connection closed")

            if websocket in self.connected_clients:
                await self.handle_client_disconnect(client_public_key)
                self.connected_clients.remove(websocket)

                logger.info(f"[+] sending client_update to neighbourhood")

                # Read the server list file assume it always exists
                with open(SERVER_NEIGHBOURHOOD_FILE, 'r') as file:
                    data = json.load(file)
                
                # Read the client list and send a client_update to all servers
                with open(CLIENT_LIST_FILE, 'r') as file:
                    client_list = json.load(file)

                message = json.dumps(self.format_m.client_update(client_list['servers'][0]['clients']))
                
                server_uri = [server["uri"] for server in data.get("servers", []) if f"ws://{HOST}:{PORT}" != server["uri"]]
                tasks = []
                ws = None
                
                for uri in server_uri:
                    try:
                        ws = self.connected_servers[uri]
                    
                    except:
                        logger.error(f"[#] Could not connect to {uri}")

                    if ws:
                        task = asyncio.create_task(self.send_to_server(ws, message))
                        tasks.append(task)

                # Wait for all tasks to complete concurrently
                await asyncio.gather(*tasks)

async def main():
    counter = 0

    keys = init_keys(logger, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)
    rsa = keys.manage()
    format_m = format_message(rsa, counter)
    ws_server = WebSocketServer(rsa, format_m)
    http_server = HTTPServer()

    logger.info("[*] Starting Server")

    try:
        async with websockets.serve(ws_server.websocket_handler, HOST, PORT):
            logger.info(f"[*] Listening on ws://{HOST}:{PORT}")

            await ws_server.send_server_hello() 
            await ws_server.send_client_update_request()

            await asyncio.gather(
                asyncio.Future(),  # Keeps the WebSocket server running
                http_server.serve()  # Start the HTTP server
            
            )
    except websockets.exceptions.InvalidHandshake as e:
        logger.error(f"[#] Handshake failed: {e}")

    except websockets.exceptions.InvalidStatusCode as e:
        logger.error(f"[#] Connection rejected: {e}")

if __name__ == "__main__":
    asyncio.run(main())
