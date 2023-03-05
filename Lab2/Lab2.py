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

        #row = findStud(studNum,csvDict)
        if studNum in csvDict:
            print("Student Found")
        else:
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

def messageGen(gradeType,csvDict,flag,studNum):
    if gradeType == 'Exam':
        if flag[-1] == 1:
            message = 'Exam 1: ' + csvDict[studNum][7]
        elif flag[-1] == 2:
            message = 'Exam 2: ' + csvDict[studNum][8]
        elif flag[-1] == 3:
            message = 'Exam 3: ' + csvDict[studNum][9]
        elif flag[-1] == 4:
            message = 'Exam 4: ' + csvDict[studNum][10]
    elif gradeType == 'All':
        message = 'Lab 1: ' +csvDict[studNum][2]+ 'Lab 2: '+csvDict[studNum][3]+ 'Lab 3: ' +csvDict[studNum][4]+ 'Lab 4: ' +csvDict[studNum][5]+ 'Midterm: ' +csvDict[studNum][6]+ 'Exam 1: ' +csvDict[studNum][7]+ 'Exam 2: ' +csvDict[studNum][8]+ 'Exam 3: ' +csvDict[studNum][9]+ 'Exam 4: ' + csvDict[studNum][10]
    elif gradeType == 'Midterm':
        message = 'Midterm: '+csvDict[studNum][6]
    elif gradeType == 'Lab 1':
        message = 'Lab 1: ' +csvDict[studNum][2]
    grade = row[gradeType]
    inputEncrypt()

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
    
def findStud(studNum,csvDict):
    
        for row in csvDict:
            if studNum in row['ID Number']:
                print ("Found Student")
                return row
        print("User Not Found")
        return 0

def printReadCSV(file):
    csvDict = {}
    with open(file, mode='r') as csv_file:
        csvReader = csv.DictReader(csv_file)
        print(type(csvReader))
        print('Data in CSV file')
        for row in csvReader:
            csvDict[row['ID Number']] = [row['Name'],
                                         row['Key'],
                                         row['Lab 1'],
                                         row['Lab 2'],
                                         row['Lab 3'],
                                         row['Lab 4'],
                                         row['Midterm'],
                                         row['Exam 1'],
                                         row['Exam 2'],
                                         row['Exam 3'],
                                         row['Exam 4']]
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