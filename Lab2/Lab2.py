import sys
import socket
import csv
import argparse
from cryptography.fernet import Fernet

HOSTNAME = 'localhost'
PORT = 50000
RECV_BUFFER_SIZE = 1024 
MAX_CONNECTION_BACKLOG = 10

#The server function which runs the whole Server
def Server():
    #Reading and saving the input csv as a dictionary 
    file = 'course_grades_2023.csv'
    csvDict = printReadCSV(file)
    
    #Creating a server socket and binding it to the local host
    serSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serSoc.bind((HOSTNAME,PORT))

    #Listening for client connection
    serSoc.listen(MAX_CONNECTION_BACKLOG)
    print('Server is listening on port', PORT)

    #When client connects
    while True:
        cliSoc,address = serSoc.accept()
        print('Connected by', address)

        #Receiving User input and splitting it 
        data = cliSoc.recv(RECV_BUFFER_SIZE)
        dataDec = data.decode()
        studNum = dataDec.split()[0]
        flag = dataDec.split()[1]
        
        #Looks for the student number in the csv dictionary 
        if studNum in csvDict:
            print('Student Found')
        else:
            print('Student Not Found')
            cliSoc.close()

        #Encrypts the students grade message using the corresponding key and sends both to the client
        encryptMessageBytes,encryptKeyBytes = inputEncrypt(messageGen(flag,csvDict[studNum]),csvDict[studNum]['Key'])
        cliSoc.sendall(encryptMessageBytes)
        cliSoc.sendall(encryptKeyBytes)
        print('Message Sent')

        # close the connection
        cliSoc.close()
        print('Ending Connection with Client')

#The client function which runs the whole Client
def Client():
    #Creating client socket
    cliSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliSoc.connect((HOSTNAME,PORT))

    # send a message to the server
    input = clientInput()
    cliSoc.send(input.encode())
    inputSplit = input.split()

    
    #Checks if the correct number of inputs were given
    if len(inputSplit)<2:
        print("Please Enter with the proper format: Student ID <flag>")
        cliSoc.close()

    flag = inputSplit[1]
    clientInputSwitch(flag)

    #Receiving the encrypted message and key from server then decrpyting and printing the grades
    message = cliSoc.recv(RECV_BUFFER_SIZE)
    key = cliSoc.recv(RECV_BUFFER_SIZE)
    message = inputDecrypt(message,key)
    print("Message Decrpyted:", message)
    cliSoc.close()

#Server Generates the message to send to client 
def messageGen(flag,studEntry):
    message = ''
    if flag == 'GG': #Checking if the GG flag was sent 
        assessList = ['GL1A','GL2A','GL3A','GL4A','GMA','GEA']
        for i in assessList:
            message += i+ ' : '
            if i == 'GEA':
                for j in studEntry[i]:
                    message += j+ ' '
            else:
                message += studEntry[i]+ ' '
    elif flag == 'GEA': #If GEA flag was sent
        message = 'Grades: '
        for i in studEntry[flag]:
            message += i+ ' '
    else: #Everything else 
        message = 'Grade: '+ studEntry[flag]
    print(message)
    return message

#Set of swtich statements printing a statement depending on the flag
def clientInputSwitch(flag):
    if flag == 'GMA':
        print('Fetching Midterm Average')
    elif flag == 'GL1A':
        print('Fetching Lab 1 Average')
    elif flag == 'GL2A':
        print('Fetching Lab 2 Average')
    elif flag == 'GL3A':
        print('Fetching Lab 3 Average')
    elif flag == 'GL4A':
        print('Fetching Lab 4 Average')
    elif flag == 'GEA':
        print('Fetching Exam Averages')
    elif flag == 'GG':
        print('Fetching All Averages')

#Reads the given csv file the stores and returns the rows into a dictionary 
def printReadCSV(file):
    csvDict = {}
    with open(file, mode='r') as csv_file:
        csvReader = csv.DictReader(csv_file)
        print(type(csvReader))
        print('Data in CSV file')
        for row in csvReader: #Goes through the csv and stores it into a dictionary 
            csvDict[row['ID Number']] = {'Name': row['Name'],
                                         'Key': row['Key'],
                                         'GL1A': row['Lab 1'],
                                         'GL2A': row['Lab 2'],
                                         'GL3A': row['Lab 3'],
                                         'GL4A': row['Lab 4'],
                                         'GMA': row['Midterm'],
                                         'GEA': [row['Exam 1'],row['Exam 2'],row['Exam 3'],row['Exam 4']]
                                        }
            print(row)
    return csvDict

#Server encrypts the message using fernet and the key corresponding to the student  
def inputEncrypt(message,key):
    message_bytes = message.encode('utf-8')
    encryption_key_bytes = key.encode('utf-8')
    fernet = Fernet(encryption_key_bytes)
    encrypted_message_bytes = fernet.encrypt(message_bytes)
    print("Encrypted Message: ", encrypted_message_bytes)
    return encrypted_message_bytes,encryption_key_bytes

#Client decrypts the message using fernet and the key 
def inputDecrypt(messageBytes,keyBytes):
    fernet = Fernet(keyBytes)
    decrpytedMessageBytes = fernet.decrypt(messageBytes)
    decrypted_message = decrpytedMessageBytes.decode('utf-8')
    return decrypted_message

#Client waits for an input 
def clientInput ():
    while True:
        inputText = input("Student # and Command: ")
        if inputText != "":
                break
    return inputText

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role', 
                        help='To run as server: python .\Lab2.py -r server | To run as client: python .\Lab2.py -r client ',
                        required=True, type=str)

    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    
    #To run as server: python .\Lab2.py -r server
    #To run as client: python .\Lab2.py -r client 
    if (args.role == 'server'):
        Server()
    elif (args.role == 'client'):
        while True:
            Client()