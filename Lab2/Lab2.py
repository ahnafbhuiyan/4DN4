import socket
import csv
import argparse
from cryptography.fernet import Fernet



HOSTNAME = 'localhost'
PORT = 50000
RECV_BUFFER_SIZE = 1024 # Used for recv.
MAX_CONNECTION_BACKLOG = 10

def Server():
    file = 'course_grades_2023.csv'
    csvDict = printReadCSV(file)
    
    serSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serSoc.bind((HOSTNAME,PORT))

    serSoc.listen(MAX_CONNECTION_BACKLOG)
    print('Server is listening on port', PORT)

    while True:
        cliSoc,address = serSoc.accept()
        print('Connected by', address)
        data = cliSoc.recv(RECV_BUFFER_SIZE)
        dataDec = data.decode()
        #print(dataDec)
        studNum = dataDec.split()[0]
        flag = dataDec.split()[1]
        
        if studNum in csvDict:
            print('Student Found')
        else:
            print('Student Not Found')
            cliSoc.close()

        encryptMessageBytes,encryptKeyBytes = inputEncrypt(messageGen(flag,csvDict[studNum]),csvDict[studNum]['Key'])
        #print(type(encryptMessageBytes))
        cliSoc.sendall(encryptMessageBytes)
        cliSoc.sendall(encryptKeyBytes)
        #serSoc.sendall(csvDict[studNum]['Key'].encode())
        print('Message Sent')

        # close the connection
        cliSoc.close()
        print('Ending Connection with Client')
        # exit()

def Client():
    cliSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliSoc.connect((HOSTNAME,PORT))

    # send a message to the server
    input = clientInput()
    cliSoc.send(input.encode())
    inputSplit = input.split()

    if len(inputSplit)<2:
        print("Please Enter with the proper format: Student ID <flag>")
        cliSoc.close()

    studNum = inputSplit[0]
    flag = inputSplit[1]

    clientInputSwitch(flag)

    message = cliSoc.recv(RECV_BUFFER_SIZE)
    key = cliSoc.recv(RECV_BUFFER_SIZE)
    message = inputDecrypt(message,key)
    print("Message Decrpyted:", message)
    cliSoc.close()

def messageGen(flag,studEntry):
    message = ''
    if flag == 'GG':
        assessList = ['GL1A','GL2A','GL3A','GL4A','GMA','GEA']
        for i in assessList:
            message += i+ ' : '
            if i == 'GEA':
                for j in studEntry[i]:
                    message += j+ ' '
            else:
                message += studEntry[i]+ ' '
    elif flag == 'GEA':
        message = 'Marks: '
        for i in studEntry[flag]:
            message += i+ ' '
    else:
        message = 'Mark: '+ studEntry[flag]
    print(message)
    return message


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

def printReadCSV(file):
    csvDict = {}
    with open(file, mode='r') as csv_file:
        csvReader = csv.DictReader(csv_file)
        print(type(csvReader))
        print('Data in CSV file')
        for row in csvReader:
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

def inputEncrypt(message,key):
    message_bytes = message.encode('utf-8')
    encryption_key_bytes = key.encode('utf-8')
    fernet = Fernet(encryption_key_bytes)
    encrypted_message_bytes = fernet.encrypt(message_bytes)
    print(type(encrypted_message_bytes))
    print("Encrypted Message: ", encrypted_message_bytes)
    return encrypted_message_bytes,encryption_key_bytes

def inputDecrypt(messageBytes,keyBytes):
    fernet = Fernet(keyBytes)
    decrpytedMessageBytes = fernet.decrypt(messageBytes)
    decrypted_message = decrpytedMessageBytes.decode('utf-8')
    return decrypted_message
    
def clientInput ():
    while True:
        inputText = input("Student # and Command: ")
        if inputText != "":
                break
    return inputText

if __name__ == '__main__':
    #roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role', 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    
    if (args.role == 'server'):
        Server()
    elif (args.role == 'client'):
        Client()
    #roles[args.role]()