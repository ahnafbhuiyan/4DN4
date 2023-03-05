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

        if studNum in csvDict:
            print("Student Found")
            messageGen(gradeType,csvDict[studNum])
        else:
            print('Student Not Found')
            cliSoc.close()

        



        # close the connection
        cliSoc.close()
        print('Ending Connection with Client')

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

    res = cliSoc.recv(RECV_BUFFER_SIZE).decode()

    cliSoc.close()

def messageGen(gradeType,studEntry):
    message = ''
    if gradeType == 'All':
        assessList = ['Lab 1','Lab 2','Lab 3','Lab 4','Midterm','Exam 1','Exam 2','Exam 3','Exam 4']
        for i in assessList:
            message += i+ ': ' +studEntry[i]+ ' '
    else:
        message = gradeType+ ': ' +studEntry[gradeType]
    print(message)
    inputEncrypt(message,studEntry['Key'])

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

def printReadCSV(file):
    csvDict = {}
    with open(file, mode='r') as csv_file:
        csvReader = csv.DictReader(csv_file)
        print(type(csvReader))
        print('Data in CSV file')
        for row in csvReader:
            csvDict[row['ID Number']] = {'Name':row['Name'],
                                         'Key':row['Key'],
                                         'Lab 1': row['Lab 1'],
                                         'Lab 2': row['Lab 2'],
                                         'Lab 3': row['Lab 3'],
                                         'Lab 4': row['Lab 4'],
                                         'Midterm':row['Midterm'],
                                         'Exam 1': row['Exam 1'],
                                         'Exam 2': row['Exam 2'],
                                         'Exam 3': row['Exam 3'],
                                         'Exam 4': row['Exam 4']}
            print(row)
    return csvDict

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