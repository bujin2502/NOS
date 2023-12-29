import xmlrpc.server
import socket

class Server:
    def symbolic_to_numeric(self, symbolic_address):
        try:
            addr_info = socket.getaddrinfo(symbolic_address, None)
            numeric_ip = addr_info[0][4][0]
            return numeric_ip
        except socket.error as e:
            print(f"Error: {e}")
            return None

    def numeric_to_symbolic(self, numeric_ip):
        try:
            symbolic_address, _, _ = socket.gethostbyaddr(numeric_ip)
            return symbolic_address
        except socket.error as e:
            print(f"Error: {e}")
            return None

server = xmlrpc.server.SimpleXMLRPCServer(("localhost", 8000))
server.register_instance(Server())
server.serve_forever()
