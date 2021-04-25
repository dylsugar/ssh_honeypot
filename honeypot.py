#!/usr/bin/env python

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import subprocess

import paramiko
from paramiko.py3compat import b, u, decodebytes


# setup logging
paramiko.util.log_to_file("demo_server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
# host_key = paramiko.DSSKey(filename='test_dss.key')
count = 0
global HOST
global PORT
global USERNAME
global PASSWORD
#print("Read key: " + u(hexlify(host_key.get_fingerprint())))


class Server(paramiko.ServerInterface):
    # 'data' is the output of base64.b64encode(key)
    # (using the "user_rsa_key" files)
    global USERNAME
    data = (
        b"AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp"
        b"fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC"
        b"KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT"
        b"UWT10hcuO4Ks8="
    )
    good_pub_key = paramiko.RSAKey(data=decodebytes(data))
    
    print("Count: ",count)
    count+=1
    def __init__(self):
        self.event = threading.Event()
        t = threading.Thread(target=self.check_channel_shell_request,args=(self.event,))
        t.start()
        self.uname = " "
        self.count = 0

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.uname = username
        return paramiko.AUTH_SUCCESSFUL

    #def check_auth_publickey(self, username, key):
    #    print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
    #    if (username == "robey") and (key == self.good_pub_key):
    #        return paramiko.AUTH_SUCCESSFUL
    #    return paramiko.AUTH_FAILED

    #def check_auth_gssapi_with_mic(
    #    self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    #):
     #   """
     #   .. note::
     #       We are just checking in `AuthHandler` that the given user is a
     #       valid krb5 principal! We don't check if the krb5 principal is
     #       allowed to log in on the server, because there is no way to do that
     #       in python. So if you develop your own SSH server with paramiko for
     #       a certain platform like Linux, you should call ``krb5_kuserok()`` in
    #        your local kerberos library to make sure that the krb5_principal
    #        has an account on the server and is allowed to log in as a user.
      #  .. seealso::
      #      `krb5_kuserok() man page
      #      <http://www.unix.com/man-page/all/3/krb5_kuserok/>`_
      #  """
      #  if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
      #      return paramiko.AUTH_SUCCESSFUL
      #  return paramiko.AUTH_FAILED

    #def check_auth_gssapi_keyex(
      #  self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    #):
       # if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
        #    return paramiko.AUTH_SUCCESSFUL
        #return paramiko.AUTH_FAILED

    #def enable_auth_gssapi(self):
    #    return True

    #def get_allowed_auths(self, username):
    #    return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


DoGSSAPIKeyExchange = True

flag = 0
user_attempt = {}
while flag == 0:
# now connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 22))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
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
        traceback.print_exc()
        sys.exit(1)

    print("Got a connection!\n\n")

    hey = True
    if hey:
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
        # wait for auth
        chan = t.accept(20)
        if chan is None:
            print("*** No channel.")
            sys.exit(1)
   
        print("Channel has been open\n\n")
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
        while True:    
            uinput = chan.recv(1024)
            chan.send(uinput)
            command = command + uinput.decode()
            if uinput.decode() == '\r':
                command = command.strip()
                chan.send("\r\n")
                each_command = command.split(' ')
                print(each_command)
                currwodir = os.getcwd()
                print(currwodir)
                if len(each_command) > 1:
                    directory = each_command[1].strip('/')
                else:
                    directory = each_command[0]

                if 'cd' in each_command:
                    try:
                        os.chdir(os.path.abspath(directory))
                        cwd = os.getcwd()
                        print("CWD: ",cwd)
                    except:
                        chan.send("-bash: cd: "+directory+": No such file or directory")
                else:
                    p = subprocess.Popen(command, shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    print(p.stdout)
                    if command == "exit":
                        break
                    stdout,stderr=p.communicate()
                    print(stdout)
                    output = ((stdout.decode()).replace('\n','   ')).encode()
                    chan.sendall(output)
                    chan.sendall_stderr(stderr)
                    chan.send_exit_status(p.returncode)
                    print(stdout)
                chan.send("\r\n")
                command = ""
                chan.send(server.uname+"@honeypot:/$ ")
        chan.close()
