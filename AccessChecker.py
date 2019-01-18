import argparse
import datetime
import ftplib
import logging
import os
from _socket import timeout, gaierror
import importlib

try:
    import certifi
except ImportError:
    os.system("pip install --user certifi")
    import certifi
try:
    import paramiko
except ImportError:
    os.system("pip install --user paramiko")
    import paramiko
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    os.system("pip install --user requests")
    import requests
    from requests.auth import HTTPBasicAuth

import urllib3


log_location: str
error_location: str



class Access:
    #attributes d'un objet d'Access

    #Localisation de la machine(IP, URL), #machine location
    location = ''
    #protocole utilisé parmi ceux précités #used protocol
    protocol = ''
    #compte : mot de passe
    login = ''
    #•résultat attendu via un code et / ou un statut,
    expected_result = ''
    #•une chaîne de caractère à retrouver dans la réponse
    expected_str = ''

    def __init__(self, n, l, p, c, s, es):
        self.line = n
        self.location = l
        self.protocol = p
        self.login = c
        self.expected_result = s
        self.expected_str = es

    def __str__(self):
        return "location: ", self.location, " protocol: ", self.protocol, " login: ", self.login.split(':')[0], "password: ", self.login.split(':')[1], " expected_result: ", self.expected_result, " expected_str: ", self.expected_str

    #Fonction check_protocol(self) pour lancer la vérification des protocoles
    def check_protocol(self):
        if(self.protocol == 'http'):
            self.http()
        elif(self.protocol == 'ftp'):
            self.ftp()
        elif (self.protocol == 'ssh'):
            self.ssh()
        elif (self.protocol == 'git'):
            self.git()
        else:
            log_error("Invalid Protocol", self.line, self.protocol)


    #une fonction par protocole, qui vérifie la connexion, qu’on arrive bien à se connecter avec les infos données par le protocole 
    def http(self):
        try:
            http = urllib3.PoolManager(ca_certs=certifi.where())
            request = http.request('GET', self.location)
            if "200" == str(request.status):
                log(self.line, self.protocol)
            else:
                log_error("Error reaching the host (status: " + str(request.status) + ")", self.protocol, self.line)
        except Exception as e:
            log_error("Host unreachable", self.protocol, self.line)

    def ftp(self):
        ftp = ftplib.FTP(self.location)
        try:
            msg: str
            if self.login is "":
                msg = ftp.login()
            else:
                msg = ftp.login(self.login.split(":")[0], self.login.split(":")[1])
            request = msg.split(" ")
        except ftplib.error_perm as e:
            request = str(e).split(" ")
        except timeout:
            log_error("Host unreachable", self.protocol, self.line)
            return
        request[1] = " ".join([x for x in request[1:]])
        if self.expected_str == request[1] and self.expected_result == request[0]:
            log(self.line, self.protocol)
        elif self.expected_result != request[0]:
            log_error("Status error. Expected '" + self.expected_result + "', got '" + request[0] + "'", self.line, self.protocol)
        elif self.expected_str != request[1]:
            log_error("Data error. Expected '" + self.expected_str + "', got '" + request[1] + "'", self.line, self.protocol)

    def ssh(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.location, username=self.login.split(":")[0], password=self.login.split(":")[1])
            stdin, stdout, stderr = client.exec_command("whoami")
            status = str(stdout.channel.recv_exit_status())
            out = stdout.read().decode("utf-8").strip("\n")
            client.close()
            if out == self.expected_str and status == self.expected_result:
                log(self.line, self.protocol)
            if out != self.expected_str:
                log_error("Data error, Expected '" + self.expected_str + "', got '" + out + "'", self.line,
                          self.protocol)
            if status != self.expected_result:
                log_error("Status error, Expected '" + self.expected_result + "', got '" + status + "'", self.line,
                          self.protocol)
        except paramiko.ssh_exception.AuthenticationException:
            log_error("Bad credentials", self.line, self.protocol)
        except gaierror as e:
            log_error("Host unreachable", self.line, self.protocol)

    def git(self):
        try:
            auth = requests.get("https://api.github.com/repos/"+self.location+"/collaborators",
                       auth=HTTPBasicAuth(self.login.split(":")[0], self.login.split(":")[1]))
            response = auth.json()
            if "message" in response:
                if "Bad" in response["message"]:
                    log_error("Bad credentials", self.line, self.protocol)
                elif "Must" in response["message"]:
                    log_error("No access to repository", self.line, self.protocol)
                elif "Not Found" == response["message"]:
                    log_error("Repository not found", self.line, self.protocol)
            else:
                log(self.line, self.protocol)
        except Exception as e:
            print(e)
            log_error("Host unreachable", self.line, self.protocol)


def log_error(message: str, line_nb: str, protocol: str) -> None:
    """
    Logging to an error file
    :param filename: The path to the error file
    :param option: The option of the logger
    :rtype: None
    """
    global error_location
    logger = logging.getLogger('1')
    handler = logging.FileHandler(error_location)
    handler.setLevel(logging.ERROR)
    handler.setFormatter(logging.Formatter('[ERROR] %(message)s'))
    logger.addHandler(handler)
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current date time with format
    logger.error(str(date) + " : " + message + " with protocol " + protocol + " (line " + line_nb + ")")
    logger.removeHandler(handler)

def log(line_nb: str, protocol: str) -> None:
    """
    Logging to a file
    :param filename: The path to the log file
    :param line_nb: The line in access file
    :param protocol: the protocol used
    :rtype: None
    """
    global log_location
    logger = logging.getLogger('2')
    handler = logging.FileHandler(log_location)
    handler.setLevel(logging.ERROR)
    handler.setFormatter(logging.Formatter('[INFO] %(message)s'))
    logger.addHandler(handler)
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current date time with format
    logger.error(str(date) + " : " + "Authorized access with protocol " + protocol + " (line " + line_nb + ")")
    logger.removeHandler(handler)

def read_file(access_file_path: str) -> list:
    """
    Reading and storage of data
    :param access_file_path: The path to the file
    :rtype: list
    """
    access_list = []

    # Reading in file
    file = open(access_file_path)
    file_content = file.readlines()
    for number, line in enumerate(file_content):
        data = line.split(';')

        # Storage the data
        url = data[0]
        protocol = data[1]
        user_name = data[2]
        expected_response_code = data[3]
        expected_response_text = data[4]

        # Creation of the object Access
        access = Access(str(number+1), url, protocol, user_name, expected_response_code, expected_response_text.rstrip())

        # Add to the list of object Access
        access_list.append(access)
    file.close()
    return access_list


def ask_incorrect_param(name: str)->str:
    """
    Ask the user for correct location until correct
    :param name: the name of the value to test
    :return: The correct location
    """
    param: str = ""
    while not os.path.exists(param):
        print("Incorrect value for " + name)
        param = input("Enter a valid path : ")
    return param


def main_function() -> None:
    global log_location, error_location

    parser = argparse.ArgumentParser(description='Check access to different machines through different protocols')
    parser.add_argument("-a", dest="access_location", help='the absolute path of the file containing the accesses',  nargs='?')
    parser.add_argument("-l", dest="log_file", help='the absolute path of the log file',  nargs='?')
    parser.add_argument("-e", dest="error_file", help='the absolute path of the error log file',  nargs='?')
    args = parser.parse_args()

    if args.access_location is None or not os.path.exists(args.access_location):
        args.access_location = ask_incorrect_param("accesses' file location")
    if args.log_file is None or not os.path.exists(args.log_file):
        args.log_file = ask_incorrect_param("log file location")
    if args.error_file is None or not os.path.exists(args.error_file):
        args.error_file = ask_incorrect_param("error log file location")

    accesses = read_file(args.access_location)

    error_location = args.error_file
    log_location = args.log_file

    for a in accesses:
        a.check_protocol()


if __name__ == "__main__":
    main_function()
