# COMPENG 4DN4 Lab 3
# Arnab Dutta - 400183053 - duttaa3
# Ahnaf Bhuiyan - 400198359 - bhuiya3
# Dwip Patel - 400190154 - pated15

import socket
import threading
import os
import argparse

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN            = 1 # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN  = 1 # 1 byte file name size field.
FILESIZE_FIELD_LEN       = 8 # 8 byte file size field.

MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 10000

# Define a dictionary of commands. The actual command field value must be a 1-byte integer. 
CMD = {
    "get" : 1,  
    "put" : 2,
    "list" : 3,
    "bye": 4
}

# Call recv to read bytecount_target bytes from the socket. Return a
# status (True or False) and the received butes (in the former case).
def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    #sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0 # total received bytes
        recv_bytes = b''    # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target-byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return(False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)            
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        #sock.settimeout(None)        
        # print("recv_bytes: Recv socket timeout!")
        return (False, b'')


class Server:
    # Set up constants
    HOSTNAME = ""
    UDP_PORT = 30000
    TCP_PORT = 30001
    BUFFER_SIZE = 1024
    SERVICE_NAME = 'Arnab, Ahnaf, and Dwip\'s File Sharing Service'
    SERVER_DIR = os.getcwd() + "/server_files/"
    BACKLOG = 5

    def __init__(self):
        # List available files on server
        print("Files in Server Directory:")
        for f in os.listdir(Server.SERVER_DIR):
            print(f)

        # Create the UDP server listen socket in the usual way.
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(("0.0.0.0", Server.UDP_PORT))
        print("Listening for service discovery messages on SDP port {} ...".format(Server.UDP_PORT))

        # Create the TCP server listen socket in the usual way.
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_socket.bind((Server.HOSTNAME, Server.TCP_PORT))
        self.tcp_socket.listen(Server.BACKLOG)
        print("Listening for file sharing connections on port  {} ...".format(Server.TCP_PORT))

        # Start udp thread
        threading.Thread(target=self.process_udp_forever).start()

        # Start tcp thread
        threading.Thread(target=self.process_tcp_forever).start()

    def process_udp_forever(self):
        while True:
            try:
                data, addr = self.udp_socket.recvfrom(Server.BUFFER_SIZE)
                decoded = data.decode(MSG_ENCODING)
                if decoded == "SERVICE DISCOVERY":
                    response = Server.SERVICE_NAME
                    self.udp_socket.sendto(response.encode(MSG_ENCODING), addr)
            except KeyboardInterrupt:
                print("1")
                exit()
            except Exception as msg:
                print(msg)
                break

    def process_tcp_forever(self):
        try:
            while True:
                self.handle_client(self.tcp_socket.accept())
        except KeyboardInterrupt:
            print("2")
        finally:
            self.tcp_socket.close()
    
    def handle_client(self, client_socket):
        connection, address = client_socket
        print("-" * 72)
        print("Connection received from {}.".format(address))
        
        while True:
            # Receive command from client
            status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
            command = int.from_bytes(cmd_field, byteorder='big')
            
            # Decode command and handle accordingly
            if command == CMD["get"]:
                self.handle_get(client_socket)
            elif command == CMD["put"]:
                self.handle_put(client_socket)
            elif command == CMD["list"]:
                self.handle_list(client_socket)
            elif command == CMD["bye"]:
                self.handle_bye(client_socket)
                break
            
    def handle_get(self, client_socket):
        connection, address = client_socket
        status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return
        filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
        if not filename_size_bytes:
            print("Connection is closed!")
            connection.close()
            return
        
        print('Filename size (bytes) = ', filename_size_bytes)

        # Now read and decode the requested filename.
        status, filename_bytes = recv_bytes(connection, filename_size_bytes)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return
        if not filename_bytes:
            print("Connection is closed!")
            connection.close()
            return

        filename = filename_bytes.decode(MSG_ENCODING)
        print('Requested filename = ', filename)
        filename = Server.SERVER_DIR + filename

        ################################################################
        # See if we can open the requested file. If so, send it.
        
        # If we can't find the requested file, shutdown the connection
        # and wait for someone else.
        try:
            file = open(filename, 'r').read()
        except FileNotFoundError:
            print("File not found")
            connection.close()                   
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes
        
        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending file: ", filename)
            print("file size field: ", file_size_field.hex(), "\n")
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return
        finally:
            connection.close()
            return

    def handle_put(self, client_socket):
        connection, address = client_socket
        status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return
        filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
        if not filename_size_bytes:
            print("Connection is closed!")
            connection.close()
            return
        
        status, filename_bytes = recv_bytes(connection, filename_size_bytes)
        if not status:
            print("Closing connection ...")            
            connection.close()
            return
        if not filename_bytes:
            print("Connection is closed!")
            connection.close()
            return
        
        status, filesize_bytes = recv_bytes(connection, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not filesize_bytes:
            print("Closing connection ...")
            connection.close()
            return
        
        filesize = int.from_bytes(filesize_bytes, byteorder='big')

        status, file_bytes = recv_bytes(connection, filesize)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not file_bytes:
            print("Closing connection ...")
            connection.close()
            return
        
        filepath = Server.SERVER_DIR + filename_bytes.decode(MSG_ENCODING)

        # Open in 'wb' mode to create new file and write bytes
        with open(filepath, "wb") as f:
            f.write(file_bytes)
        f.close()

    def handle_list(self, client_socket):
        connection, address = client_socket
        # Get list of files in shared directory
        files = os.listdir(Server.SERVER_DIR)
        file_list = ""
        for i in range(len(files)):
            if i != (len(files) - 1):
                file_list = file_list + files[i] + "\n"
            else:
                file_list = file_list + files[i]
        file_list = (file_list).encode(MSG_ENCODING)
        # Send file list to client
        connection.send(file_list + len(file_list).to_bytes(4, byteorder='big'))

    def handle_bye(self, client_socket):
        connection, address = client_socket
        print("Closing connection")
        connection.close()
        return

class Client:
    # Set up constants
    HOSTNAME = "localhost"
    UDP_PORT = 30000
    TCP_PORT = 30001
    RECV_SIZE = 10
    SERVICE_DISCOVERY_MSG = "SERVICE DISCOVERY"
    DOWNLOADED_FILE_NAME = "filedownload.txt"
    CLIENT_DIR = os.getcwd() + "/client_files/"

    def __init__(self):
        self.get_socket()
        self.handle_commands()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            exit()
    
    def handle_commands(self):
        while True:
            command = input("Enter a command: ")
            if command == "scan":
                self.scan()
            elif command == "llist":
                self.local_list()
            elif command == "rlist":
                self.remote_list()
            elif command.startswith("connect"):
                address = command.split(" ")[1]
                port = int(command.split(" ")[2])
                self.connect((address, port))
            elif command.startswith("get"):
                file_name = command.split(" ")[1]
                self.get((file_name))
            elif command.startswith("put"):
                file_name = command.split(" ")[1]
                self.put((file_name))
            elif command == "bye":
                self.bye()
                exit()

    def scan(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        encoded_msg = Client.SERVICE_DISCOVERY_MSG.encode(MSG_ENCODING)
        udp_socket.sendto(encoded_msg, ("255.255.255.255", Client.UDP_PORT))
        response, addr = udp_socket.recvfrom(1024)
        decoded_response = response.decode(MSG_ENCODING)
        print(decoded_response, " found at ", str(addr[0]), str(Server.UDP_PORT))

    def connect(self, addr):
        self.socket.connect(addr)
    
    def local_list(self):
        for f in os.listdir(Client.CLIENT_DIR):
            print(f)
    
    def remote_list(self):
        cmd_field = CMD["list"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        self.socket.sendall(cmd_field)

        rlist_size = int(self.socket.recv(1).hex(), 16)
        rlist = self.socket.recv(rlist_size).decode()
        print(rlist)
    
    def get(self, file_name):
        # Create the packet cmd field.
        cmd_field = CMD["get"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field_bytes = file_name.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet.
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())
        
        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        ################################################################
        # Process the file transfer repsonse from the server
        
        # Read the file size field returned by the server.
        status, file_size_bytes = recv_bytes(self.socket, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            self.socket.close()
            return

        print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            self.socket.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size = ", file_size)

        # self.socket.settimeout(4)                                  
        status, recvd_bytes_total = recv_bytes(self.socket, file_size)
        if not status:
            print("Closing connection ...")            
            self.socket.close()
            return
        # print("recvd_bytes_total = ", recvd_bytes_total)
        # Receive the file itself.
        try:
            # Create a file using the received filename and store the
            # data.
            file_loc = Client.CLIENT_DIR + file_name
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), file_name))

            with open(file_loc, 'w') as f:
                recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
                f.write(recvd_file)
            print(recvd_file)
        except KeyboardInterrupt:
            print("el ahnaf")
            exit(1)
    
    def put(self, file_name):
        # Create the packet cmd field.
        cmd_field = CMD["put"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field_bytes = file_name.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_bytes = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

         # Open the file and convert it to bytes
        try:
            file_path = Client.CLIENT_DIR + file_name
        except FileNotFoundError:
            print("File not found")
            self.socket.close()
            return
        
        f = open(file_path, 'r').read()
        file_size_field = len(f).to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        pkt = cmd_field + filename_size_bytes + filename_field_bytes + file_size_field + f.encode(MSG_ENCODING)

        try:
            # Send the packet to the connected client.
            self.socket.sendall(pkt)
            print("Sending file: ", file_name)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            self.socket.close()
            return
        
    def bye(self):
        cmd_field = CMD["bye"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        self.socket.sendall(cmd_field)
        self.socket.close()
        


if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()