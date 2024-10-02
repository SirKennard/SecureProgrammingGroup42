import json
import base64

class format_message:
    def __init__(self, rsa_handler, counter) -> None:
        self.counter = counter
        self.rsa_handler = rsa_handler

    def signed_data(self, data: json) -> json:
        self.counter += 1
        signiture = self.rsa_handler.sign((json.dumps(data) + str(self.counter)).encode())

        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": base64.b64encode(signiture).decode('utf-8')
        }

        return message
    
    def server_hello(self, ip_addr, port = 80) -> json:
        data = {
            "type": "server_hello",
            "sender": ip_addr + ":" + str(port)
        }

        return self.signed_data(data)
    
    def client_update(self, client_list) -> json:
        message = {
            "type": "client_update",
            "clients": client_list
        }

        return message
    
    def client_update_request(self) -> json:
        message = {
            "type": "client_update_request"
        }

        return message
    
    def client_list(self, servers) -> json:
        message = {
            "type": "client_list",
            "servers": servers
        }

        return message
