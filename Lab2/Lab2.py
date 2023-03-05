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
        gradeType = serverInputSwitch(flag)

        row = findStud(studNum,csvDict,file)

        if row == 0:
            cliSoc.close()
        # else:
        #     if gradeType == 'Exam':

            # grade = row[flag]
            # inputEncrypt()



        # close the connection
        cliSoc.close()
        print('Ending Connection with Client')

def Client():
    cliSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliSoc.connect((HOSTNAME,PORT))

    # send a message to the server
    input = clientInput()
    cliSoc.send(input.encode())
    studNum = input.split()[0]
    flag = input.split()[1]
    clientInputSwitch(flag)

    res = cliSoc.recv(RECV_BUFFER_SIZE).decode()

    cliSoc.close()

def serverInputSwitch(flag):
    if flag == 'GMA':
        print('Received GMA command from client')
        return 'Midterm'
    elif flag == 'GL1A':
        print('Received GL1A command from client')
        return 'Lab 1'
    elif flag == 'GL2A':
        print('Received GL2A command from client')
        return 'Lab 2'
    elif flag == 'GL3A':
        print('Received GL3A command from client')
        return 'Lab 3'
    elif flag == 'GL4A':
        print('Received GL4A command from client')
        return 'Lab 4 '
    elif flag == 'GEA':
        print('Received GEA command from client')
        return 'Exam'
    elif flag == 'GG':
        print('Received GG command from client')
        return 'All'
    else:
        print('Invalid input')
        return 0

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
        print('Fetching Exam Average')
    elif flag == 'GG':
        print('Fetching All Average')
    
def findStud(studNum,csvDict,file):
    with open(file, mode='r') as csv_file:
        csvDict = csv.DictReader(csv_file)
        for row in csvDict:
            if studNum in row['ID Number']:
                print ("Found Student")
                return row
        print("User Not Found")
        return 0

def printReadCSV(file):
    with open(file, mode='r') as csv_file:
        csvReader = csv.DictReader(csv_file)
        print(type(csvReader))
        print('Data in CSV file')
        for row in csvReader:
            print(row)

def inputEncrypt(message,key):
    message_bytes = message.encode('utf-8')
    encryption_key_bytes = key.encode('utf-8')
    fernet = Fernet(encryption_key_bytes)
    encrypted_message_bytes = fernet.encrypt(message_bytes)
    print("Encrypted Message: ", encrypted_message_bytes)
    
    
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