import base64
import os
import socket
import sys
import threading
import subprocess
import time
import paramiko



host_key = paramiko.RSAKey(filename="test_rsa.key")
class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        t = threading.Thread(target=self.check_channel_shell_request,args=(self.event,))
        t.start()
        self.uname = " "

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.uname = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


# START of program is here --------------------------------------------------------------
argument = sys.argv
PORT = 0
if '-p' in argument and len(argument) == 3:
    PORT = int(argument[2])
print("argument: ",argument)
flag = 0
user_attempt = {}
while flag == 0:
# now connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", PORT))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        sys.exit(1)

    HOST = socket.gethostbyname(socket.gethostname())
    try:
        sock.listen(100)
        print("\n\n*************************************************************\n\n")
        print("\n\nThe Homework 5 SSH Honeypot Server is booting........\n\n")
        print("Server is Listening for connection ...\n\n")
        client, addr = sock.accept()
    except Exception as e:
        print("*** Listen/accept failed: " + str(e))
        sys.exit(1)

    print("Got a connection!\n\n")

    t = paramiko.Transport(client)
    t.set_gss_host(socket.getfqdn(""))
    t.load_server_moduli()
    t.add_server_key(host_key)
    server = Server()
    f = open("usernames.txt",'r')
    raw_output = f.readlines()
    user_list = []
    for x in raw_output:
        x = x.strip()
        user_list.append(x)

    try:
        t.start_server(server=server)
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)

    print("Server has been chosen\n\n")
    print("Press 'Enter' for Password\n\n")
    
    chan = t.accept(20)
    if chan is None:
        print("*** No channel.")
        sys.exit(1)
   
    print("Channel has been opened\n\n")
    server.event.wait(10)
    if not server.event.is_set():
        print("*** Client never asked for a shell.")
        sys.exit(1)
       
    if server.uname not in user_list:
        print(server.uname,"not Authentic:\n\n")
        if server.uname not in user_attempt:
            user_attempt[server.uname]=0
        else:
            user_attempt[server.uname]+=1
        if user_attempt[server.uname] < 6:
            print(server.uname," try: ",user_attempt[server.uname],"\n\n")
            chan.close()
            sock.close()
            print("Client connection channel has been closed\n\n")
            continue
        print("User ",server.uname," is not Authentic, but # Attempts > 5\n\n")
    print("User",server.uname," is Authentic\n\n")

    chan.send("\r\n\r\n######################################## HW5 Honeypot SSH Server ########################################\r\n\r\n")
    chan.send("\n********************************************************")
    chan.send("\r\n\r\nWelcome to the Hw5 SSH Server\r\n\r\n")
    chan.send("\r\n\r\n---Type 'exit' to exit SSH Server\r\n\n")
    chan.send("*********************************************************\r\n")
    chan.send(server.uname+"@honeypot:/$ ")
    command = ""
    add_dir = ''
    while True:    
        chan.settimeout(60)
        try:
            uinput = chan.recv(1024)
        except socket.timeout:
            print("Socket channel timeout: past 60 seconds")
            break

        chan.send(uinput)
        command = command + uinput.decode()
        if uinput.decode() == '\r':
            command = command.strip()
            chan.send("\r\n")
            each_command = command.split(' ')
            print("Command breakdown: ",each_command)
            
            if 'cd' in each_command:
                try:
                    if each_command[1][0]=='/':
                        os.chdir(os.path.abspath('..'))
                        os.chdir(os.path.abspath(each_command[1][1:]))
                        add_dir = each_command[1]
                    else:
                        os.chdir(os.path.abspath(each_command[1]))
                        add_dir = '/'+each_command[1].strip('./')
                    cwd = os.getcwd()
                    if each_command[1] == "..":
                        add_dir=''
                    print("Used cd - new CWD: ",cwd)
                except:
                    chan.send("-bash: cd: "+each_command[1]+": No such file or directory\r\n")
            else:
                p = subprocess.Popen(command, shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                if command == "exit":
                    print("Terminating connection with User",server.uname)
                    break
                stdout,stderr=p.communicate()
                output = (stdout.decode())
                output = output.strip()
                output = output.replace('\n','    ')
                output+='\r\n'
                output = output.encode()
                chan.sendall(output)
                chan.sendall_stderr(stderr)
                chan.send_exit_status(p.returncode)
                print("Byte form output",stdout)
            #chan.send("\r\n")
            command = ""
            chan.send(server.uname+"@honeypot:"+add_dir+"/$ ")
    chan.close()
