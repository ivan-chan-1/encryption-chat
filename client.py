import socket
import sys
import json
import threading
import time
import rsa
from base64 import b64encode, b64decode

SERVER_IP = sys.argv[1]
SERVER_PORT = int(sys.argv[2])
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
COMMANDS = ["msg", "logout", "conn"]
PROMPT = """
Enter one of the following commands:
> conn
> msg
> logout
"""

private_key = None
public_key = None
partner_key = None

# Prompt user to authenticate until successful
def authenticate(client):
    global private_key
    global public_key

    while True:
        res = client.recv(2048).decode()
        if (res != ""):
            res = json.loads(res)
        
        # Check if method is auth, if not don't continue prompting
        if (res["method"] != "auth"):
            print(res["data"])
            break
        
        # Prompt client to authenticate
        print("Please login")
        username = input("Username: ")
        password = input("Password: ")
        data = json.dumps({ "method": "auth", "data": f"{username} {password}" })
        client.send(data.encode())

    (public_key, private_key) = rsa.newkeys(1024)
    client.send(json.dumps({ "method": "conn", "data": b64encode(public_key.save_pkcs1("PEM")).decode("utf-8") }).encode())
    
    return username

# Check and print received messages from server until client logs out
def client_recv(client):
    global partner_key

    # Continually check for messages to receive
    while True:
        res = client.recv(2048)
        res = res.decode()

        # Transform message into JSON and print the data
        res = json.loads(res)
        
        # Check if message has logout method
        # If so, exit the thread
        if res["method"] == "conn":
            partner_key = rsa.PublicKey.load_pkcs1(b64decode(res["data"].encode("utf-8")), "PEM")
            print("Secure connection established")
        elif (res["method"] == "logt"):
            break
        else:
            data = res["data"].encode("utf-8")
            
            try:
                print(rsa.decrypt(b64decode(data), private_key).decode('utf-8'))
            except Exception as e:
                pass

def client_send(client):
    while True:
        time.sleep(0.1)

        # Prompt the client for input
        print(PROMPT)
        raw_arg = input("> ")
        arg = raw_arg.split(maxsplit=2)
        argNum = len(arg)

        # Check if valid command
        if (arg[0] not in COMMANDS):
            print("Error: Invalid command")
            continue
        
        # Form the data segment to send to server
        data = ""
        if (arg[0] == "msg" and check_args(3, argNum)):
            data = json.dumps({ "command": arg[0], "host": arg[1], "data": b64encode(rsa.encrypt(arg[2].encode('utf-8'), partner_key)).decode("utf-8") })
        elif (arg[0] == "logout" and check_args(1, argNum)):
            data = json.dumps({ "command": arg[0] })
        elif (arg[0] == "conn" and check_args(2, argNum)):
            data = json.dumps({ "command": arg[0], "host": arg[1] })
            
        if data != "":
            client.send(data.encode())

# Check if the correct number of arguments have been inputted
def check_args(expected, actual):
    if (expected != actual):
        print("Error: Invalid argument(s)")
        return False
    
    return True

# Create client socket to communicate with server, and build connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect(SERVER_ADDR)

    username = authenticate(client)

    # Create threads to handle receiving and sending
    recv_thread = threading.Thread(target=client_recv, args=(client, ))
    send_thread = threading.Thread(target=client_send, args=(client, ), daemon=True)

    # Start threads
    recv_thread.start()
    send_thread.start()

    recv_thread.join()
    print(f"Goodbye {username}!")