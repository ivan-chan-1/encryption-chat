import socket
import threading
import sys
import json
from datetime import datetime

# Setting constants
SERVER_HOST = "127.0.0.1"
SERVER_PORT = int(sys.argv[1])
SERVER_ADDR = (SERVER_HOST, SERVER_PORT)

# Global variables
credentials = ["Ivan 1234", "Chan 1234"]
active_usrs = {}
active_keys = {}

# Creating locks
act_lock = threading.Lock()
key_lock = threading.Lock()

# Create server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(SERVER_ADDR)
server.listen()
print(f"Server listening")

# Authenticates client, then listens for requests from clients        
def handle_client(client, client_addr):
    username = authenticate_client(client, client_addr)
    if (username is None):
        return
    server_send(client, username)

# Authenticates client
def authenticate_client(client, client_addr):
    # Prompt attempts to sign in
    while True:
        # Prompt auth and receive response
        client.send(json.dumps({ "method": "auth" }).encode())
        res = json.loads(client.recv(2048).decode())
        
        # Check username and password
        username = res["data"].split()[0]

        # Check valid credentials
        if (res["data"] in credentials):
            client.send(json.dumps({ "method": "send", "data": f"Hello, {username}" }).encode())
            break
    
    with act_lock:
        active_usrs[username] = client

    while True: 
        res = client.recv(2048).decode()
        if res != "":
            res = json.loads(res); 
            if res.get("method") == "conn":
                with key_lock:
                    active_keys[username] = res["data"]
                    print("Public key of " + username + " stored")
                break
    
    print(f"{username} logged in")
    return username

# Listens for requests from clients and issues responses according to given command
def server_send(client, username):
    while True:
        res = client.recv(2048).decode()
        if (res == ""):
            break

        res = json.loads(res)
        with act_lock:
            if (res["command"] == "msg"):
                msg(username, res["host"], res["data"])
            elif (res["command"] == "logout"):
                logout(username)
            elif (res["command"] == "conn"):
                conn(username, res["host"])

# Checks msg
def msg(sender, receiver, data):    
    if (receiver == sender):
        send(sender, "Error: Cannot send message to yourself")
        return
    elif (active_usrs.get(receiver) is None):
        send(sender, "Error: Invalid/Offline user")
        return
    
    timestamp = datetime.now().strftime('%d/%m/%Y %H:%M')
    send(receiver, json.dumps({ "method": "send", "data": data }))
    send(sender, json.dumps({ "method": "send", "data": f"{timestamp}: message sent to {receiver}" }))

# Sends message to receiver
def send(receiver, data):
    active_usrs[receiver].send(data.encode())

def conn(sender, receiver):
    active_usrs[sender].send(json.dumps({ "method": "conn", "host": receiver, "data": active_keys[receiver] }).encode())
    active_usrs[receiver].send(json.dumps({ "method": "conn", "host": sender, "data": active_keys[sender] }).encode())

# Logs out
def logout(sender):
    active_usrs[sender].send(json.dumps({ "method": "logt", "data": "Logging out" }).encode())
    active_usrs.pop(sender)

# Create one thread for each client that is accepted
try:
    while True:
        client, client_addr = server.accept()
        print(f"Connection established with {client_addr}")
        client_thread = threading.Thread(target=handle_client, args=(client, client_addr))
        client_thread.start()
except KeyboardInterrupt:
    print("\nServer closing")
finally:
    server.close()