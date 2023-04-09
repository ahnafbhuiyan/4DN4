# COMPENG 4DN4 Lab 4
# Arnab Dutta - 400183053 - duttaa3
# Ahnaf Bhuiyan - 400198359 - bhuiya3
# Dwip Patel - 400190154 - pated15
# Group 38

########################################################################

import socket
import argparse
import sys
import threading
import json

########################################################################

# MultiCast Parameters
MULTICAST_ADDRESS = "239.0.0.10"
MULTICAST_PORT = 2000
RX_IFACE_ADDRESS = "0.0.0.0"
RX_BIND_ADDRESS = "0.0.0.0"
MULTICAST_ADDRESS_PORT = (MULTICAST_ADDRESS, MULTICAST_PORT)
BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)
MSG_ENCODING = "utf-8"

# Other Parameters
TIMEOUT = 1
TTL = 1 # Hops
TTL_SIZE = 1 # Bytes
TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

RECV_SIZE = 2048
BACKLOG = 10

class Server:

    HOSTNAME = ""
    TCP_PORT = 30000
    
    def __init__(self):
        self.thread_list = []
        self.list_of_chatrooms = []
        
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.TCP_PORT))

            self.socket.listen(BACKLOG)
            print("Chat Room Directory Server Listening on port {}...".format(Server.TCP_PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

        self.process_connections_forever()

    def process_connections_forever(self):
        try:
            while True:
                new_client = self.socket.accept()

                # Create a new thread for each new client that connects
                new_thread = threading.Thread(target=self.handle_client,
                                              args=(new_client,))
                print("Connection established.")
                # Record the new thread.
                self.thread_list.append(new_thread)

                # Start the new client thread
                print("Client thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def handle_client(self, client):
        connection, address = client
        print("-" * 72)

        while True:
            try:
                # Receive bytes over the TCP connection
                recvd_bytes = connection.recv(RECV_SIZE)

                if len(recvd_bytes) == 0:
                    print("Closing client connection")
                    connection.close()
                    break

                flag = False
                recvd_str = json.loads(recvd_bytes)
                if (recvd_str[0] == "makeroom"):
                    self.handle_makeroom(client, recvd_str, connection, flag)
                elif (recvd_str[0] == "getdir"):
                    self.handle_getdir(client, connection)
                elif (recvd_str[0] == "deleteroom"):
                    self.handle_delete(client, connection, recvd_str, recvd_bytes)
                else:
                    pass
                    
            except KeyboardInterrupt:
                print()
                print("Closing client connection")
                connection.close()
                break
    
    def handle_makeroom(self, client, recvd_str, connection, flag):
        for items in self.list_of_chatrooms:
            if(items[0] == recvd_str[1]):
                flag = True
            else:
                pass
        if (flag == False):
            self.list_of_chatrooms.append(recvd_str[1:])
            print(self.list_of_chatrooms)
            msg = "New room is created"
        else:
            msg = "Duplicated room name is sent"
        feedback = json.dumps(msg)
        connection.sendall(feedback.encode(MSG_ENCODING))
    
    def handle_getdir(self, client, connection):
        chat_addr = [] 
        for items in self.list_of_chatrooms:
            chat_addr.append(items)
        serial_chat_addr = json.dumps(chat_addr)
        connection.sendall(serial_chat_addr.encode(MSG_ENCODING))
    
    def handle_delete(self, client, connection, recvd_str, recvd_bytes):
        for items in self.list_of_chatrooms:
            if(items[0] == recvd_str[1]):
                self.list_of_chatrooms.remove(items)
        print(self.list_of_chatrooms)
        connection.sendall(recvd_bytes)

class Client:

    SERVER_HOSTNAME = socket.gethostname()
    RECV_SIZE = 2048

    def __init__(self):
        self.flag_start = True
        self.thread_list_c = []
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)
        self.handle_server()

    def handle_console_input(self):
        # Prompting the user for a Command
        while True:
            self.input_text = input("Enter a Command: ")
            if self.input_text != '':
                break

    def handle_server(self):
        while True:
            try:
                self.handle_console_input()
                console_str = self.input_text.split(" ")

                if (console_str[0] == "connect"):
                    self.handle_connect()
                elif (console_str[0] == "makeroom"):
                    self.handle_makeroom(console_str)
                elif(console_str[0] == "name"):
                    self.handle_name(console_str)
                elif(console_str[0] == "getdir"):
                    self.handle_getdir(console_str)
                elif(console_str[0] == "bye"):
                    self.handle_bye()
                elif(console_str[0] == "deleteroom"):
                    self.handle_deleteroom(console_str)
                elif(console_str[0] == "chat"):
                    self.handle_chat(console_str)
                else: 
                    pass
            except (KeyboardInterrupt):
                print()
                print("Closing server connection")
                self.socket.close()
                sys.exit()
    
    def handle_connect(self):
        try:
            # Connect to the server
            print("Attempting to set connection with CDRS...")
            self.socket.connect((Client.SERVER_HOSTNAME, Server.TCP_PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def handle_makeroom(self, input):
        makeroom_info = json.dumps(input)
        self.connection_send(makeroom_info)
        self.connection_receive(input)
    
    def handle_name(self, input):
        print("Client Username is set to ", input[1])
        self.username = input[1]
    
    def handle_getdir(self, input):
        getdir_info = json.dumps(input)
        self.connection_send(getdir_info)
        self.connection_receive(input)
    
    def handle_bye(self):
        print("Client TCP connection closed")
        self.socket.close()
    
    def handle_deleteroom(self, input):
        print("Deleting Chatroom ", input[1])
        del_info = json.dumps(input)
        self.connection_send(del_info)
        self.connection_receive(input)
    
    def handle_chat(self, input):
        for item in self.chatroom_list:
            if (input[1] == item[0]):
                address_bport = (str(item[1]), int(item[2]))
        print(address_bport)
        self.flag_start = True
        # self.create_udp_send_socket(address_bport)
        if (self.flag_start):
            self.create_udp_recv_socket(address_bport)
        #else:
        #self.flag_start = True
            msg = self.username + " has joined the chat."
            self.udp_socket.sendto(msg.encode(MSG_ENCODING), address_bport)
            udp_thread = threading.Thread(target=self.udp_handler,
                                    args=(address_bport,))
        # Start the new thread running.
            udp_thread.start()
            self.udp_recv()
    
    def create_udp_send_socket(self, address_bport):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL_BYTE)
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def create_udp_recv_socket(self, address_bport):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            ############################################################            
            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that deterimines what packets make it to the
            # UDP app.
            
            ############################################################   
            bind_address = (Client.SERVER_HOSTNAME, address_bport[1])
            self.udp_socket.bind(bind_address)
            print("Chat Room Directory Server listening on port", address_bport[1])
            
            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################
                        
            multicast_group_bytes = socket.inet_aton(address_bport[0])

            print("Multicast Group: ", address_bport[0])

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", address_bport[0],"/", RX_IFACE_ADDRESS)
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)
        
    def udp_handler(self, address_bport):
        self.udp_send(address_bport)
        udp_thread = threading.Thread(target=self.udp_handler,
                                args=(address_bport,))
        #Start the new thread running.
        udp_thread.start()
        self.udp_recv()
    
    def udp_send(self, address_bport):
        try:
            # sendmsg = input(self.username + ": ")
            sendmsg = input('')
            sendmsg_encode = sendmsg.encode('ASCII')
            if (sendmsg_encode == b'\x1d'):
                self.flag_start = False
                try:
                    # Create an IPv4 TCP socket.
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                except Exception as msg:
                    print(msg)
                    sys.exit(1)
                self.handle_connect()
                self.handle_console_input()
                self.udp_socket.close()
            else:
                message = self.username + ": " + sendmsg
                self.udp_socket.sendto(message.encode(MSG_ENCODING), address_bport)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
            print("Closing server connection")
            self.udp_socket.close()
            sys.exit()       

    def udp_recv(self):
        while (self.flag_start):
            try:
                # Receive and print out text. The received bytes objects
                # must be decoded into string objects.
                recvd_bytes, address = self.udp_socket.recvfrom(RECV_SIZE)
                recvd_bytes_decoded = recvd_bytes.decode(MSG_ENCODING)
                # recv will block if nothing is available. If we receive
                # zero bytes, the connection has been closed from the
                # other end. In that case, close the connection on this
                # end and exit.
                if len(recvd_bytes) == 0:
                    print("Closing server connection ... ")
                    self.udp_socket.close()
                    sys.exit(1)
                #if(recvd_bytes_decoded == "/exit"):
                #    self.flag_start = False
                #    self.get_socket()
                #    self.connect_to_server()
                #    self.send_console_input_forever()
                #    self.udp_socket.close()
                #else:
                if(self.flag_start):
                    print(recvd_bytes_decoded)    
                
            except Exception as msg:
                print(msg)
            except KeyboardInterrupt:
                print(); exit()
                
    def connection_send(self, input_text):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(input_text.encode(MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def connection_receive(self, input_id):
        self.chatroom_list = []
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_SIZE)
            recvd_bytes_decoded = json.loads(recvd_bytes)

            if len(recvd_bytes) == 0:
                print("Closing client connection ... ")
                self.socket.close()
                sys.exit(1)

            if (input_id[0] == "getdir"):
                print("List of rooms: ", recvd_bytes_decoded)
                self.chatroom_list = recvd_bytes_decoded
            elif (input_id[0] == "makeroom"):
                if (recvd_bytes_decoded == "Duplicated room name is sent"):
                    print("This room is already created, please create a different room")
            else:
                pass
                
        except Exception as msg:
            print(msg)
            sys.exit(1)    


########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',  
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################
