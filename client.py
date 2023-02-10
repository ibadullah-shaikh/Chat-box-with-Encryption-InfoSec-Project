from tkinter import *
import tkinter as tk
import tkinter.ttk as tkk
import threading
import socket
import sys
import os
import base64
import hashlib
from Cryptodome.Cipher import AES as domeAES
from Cryptodome.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import AES as cryptoAES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode
from base64 import b64encode
from Crypto.Util.Padding import pad, unpad



BLOCK_SIZE = AES.block_size
__key__ =__key__ = hashlib.sha256(os.urandom(256 // 8)).digest()

def encrypt_publickey(raw):
    pu_key = RSA.import_key(open('server_public_key.pem').read())
    cipher = PKCS1_OAEP.new(pu_key)
    ciphertext = cipher.encrypt(raw)
    return ciphertext


def decrypt_privatekey(raw):
    pr_key = RSA.import_key(open('client_private_key.pem').read())
    cipher = PKCS1_OAEP.new(pr_key)
    plaintext = cipher.decrypt(raw)
    global __key__
    __key__ = plaintext
    return plaintext


def encrypt_CFB(raw):
    global __key__
    __key__ = hashlib.sha256(os.urandom(256 // 8)).digest()
    BS = cryptoAES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(cryptoAES.block_size)
    cipher = cryptoAES.new(key= __key__, mode= cryptoAES.MODE_CFB,iv= iv)
    a= base64.b64encode(iv + cipher.encrypt(raw))
    IV = Random.new().read(BLOCK_SIZE)
    aes = domeAES.new(__key__, domeAES.MODE_CFB, IV)
    b = base64.b64encode(IV + aes.encrypt(a))
    return b

def decrypt_CFB(enc):
    passphrase = __key__
    encrypted = base64.b64decode(enc)
    IV = encrypted[:BLOCK_SIZE]
    aes = domeAES.new(passphrase, domeAES.MODE_CFB, IV)
    enc = aes.decrypt(encrypted[BLOCK_SIZE:])
    unpad = lambda s: s[:-ord(s[-1:])]
    enc = base64.b64decode(enc)
    iv = enc[:cryptoAES.block_size]
    cipher = cryptoAES.new(__key__, cryptoAES.MODE_CFB, iv)
    b= unpad(base64.b64decode(cipher.decrypt(enc[cryptoAES.block_size:])).decode('utf8'))
    return b


def encrypt_CBC(data):
    global __key__
    __key__ = hashlib.sha256(os.urandom(256 // 8)).digest()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(__key__, AES.MODE_CBC, iv)
    return b64encode(iv +cipher.encrypt(pad(data.encode('utf-8'),AES.block_size)))

def decrypt_CBC(data):
  raw = b64decode(data)
  cipher = AES.new(__key__, AES.MODE_CBC, raw[:AES.block_size])
  b= unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size)
  return b.decode()


thread_list = []

# this function checks for the correct ip and port number
def IP_checker(ip):
    try:
        ip, port = ip.split(':')
    except:
        return 0
    
    try:
        if int(port) in range(0, 65535):
            pass
        else:
            return 0
    except:
        return 0

    try:
        ip_octates = ip.split(".")
    except:
        return 0
    
    for octate in ip_octates:
        try:
            if int(octate) in range(0,255):
                pass
            else:
                return 0
        except:
            return 0
    
    try:
        if int(ip_octates[3]) == 0:
            return 0
        else:
            pass
    except:
        return 0

    return 1
    


def disconnect(lost=False, Connection=False, end=False):
    global sock, Connected

    for t in thread_list:
        try:
            t.kill()
            t.join()
        except:
            pass
    thread_list.clear()
    try:
        sock.close()
    except:
        pass
    Connected = False
    if Connection and not end:
        ip_label_editor("Couldn't Connect to the Server ~!")
        return
    elif not lost and not end:
        ip_label_editor("Disconnected ~ You Can Connect to Different Server Now")
        print_message("Left the Chat !")


def Connect():
    global Connected, sock, inp
    if not Connected:
        Connected = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            inp = portinput.get(1.0, "end-1c")
            portinput.delete(1.0, tk.END)
        except:
            ip_label_editor("Please Enter a Valid IP Address")
            return
        if IP_checker(inp):
            ip_label_editor("Connecting To IP "+ str(inp))
            t1 = threading.Thread(target=connect_on_port, args=(inp,))
            t1.start()
            thread_list.append(t1)
        else:
            ip_label_editor("Please Enter a Valid IP Address")
    else:
        portinput.delete(1.0, tk.END)
        ip_label_editor("Please Disconnect First ~@")


def connect_on_port(ip_address):
    ip, port = ip_address.split(":")
    try:
        sock.connect((ip, int(port)))
    except:
        disconnect(Connection=True)
        sys.exit()

    ip_label_editor("Connected to Server : " + ip_address)
    print_message("Joined The Chat with Server " + ip_address)
    t2 = threading.Thread(target=recv_from_port, args=())
    t2.start()
    thread_list.append(t2)

def recv_from_port():
    while True:
        try:
            msg = sock.recv(1024)
            print(msg)
            print("\n")
            msg1 = msg
            ch1 = msg1[len(msg1)-2:]
            ch1 = ch1.decode()
            if(ch1=='ae'):
             msg1 = msg1[:-2]
             msg2 = msg1[len(msg1)-256:] #message to be decrypted by privtae key and it is key for aes
             aes = msg1[:-256]    #message to be decrypted by aes algo
             print(msg2)
             print("\n")
             print(aes)
             decrypt_privatekey(msg2)
             decrypted_data = decrypt_CFB(aes)
            else:
             msg1 = msg1[:-2]   
             msg2 = msg1[len(msg1)-256:]
             aes = msg1[:-256]
             print(aes)
             print("\n")
             print(msg2)
             print("\n")
             print(msg1)
             decrypt_privatekey(msg2)
             decrypted_data = decrypt_CBC(aes)

            print_message("Server :"+decrypted_data)
            
        except:
            ip_label_editor("Connection Lost ~! Connect Again With the Server")
            print_message("Connection Lost From the Server ~")
            disconnect(lost=True)
            break

def send_on_port(msg):
    ip_label_editor("")
    ch = str(var.get())
    if(ch=='1'):
        encrypted_data =encrypt_CFB(msg)
        print(b"AES_ENC_DATA: "+encrypted_data) #AES ENC DATA
        print("\n")
        encrypted_key = encrypt_publickey(__key__) #
        print(b"CLIENT_AES_ENC_KEY: "+encrypted_key)
        print(len(encrypted_key))
        print("\n")
        print("\n")
        encrypted_data = encrypted_data + encrypted_key + b'ae'
        print(encrypted_data)
        print("\n")
        
        print_enc_text(encrypted_data)
        sock.send(encrypted_data)
    else:
        encrypted_data =encrypt_CBC(msg)
        print(encrypted_data)
        print(len(encrypted_data))
        encrypted_key = encrypt_publickey(__key__)
        print(encrypted_key)
        print(len(encrypted_key))
        encrypted_data = encrypted_data + encrypted_key + b'fc'
        print(encrypted_data)
        print(len(encrypted_data))
        print_enc_text(encrypted_data)
        sock.send(encrypted_data)



def clearlist():
    messagelist.delete(0, tk.END)

def ip_label_editor(msg):
    iplabel['text'] = ''
    iplabel.config(text = msg)

def print_enc_text(txt):
    window=Tk() 
    window.title('Encrypted Text')
    window.geometry("500x400")
    lbl=Label(window, text="Encrypted Text:",font='Helvetica 18 bold').place(x=10,y=10)
    messagelist = tk.Listbox(window,width = 79, height = 18)
    messagelist.place(x=10, y=50)
    messagelist.insert("end", txt)
    h=Scrollbar(window, orient='horizontal')
    h.pack(side=BOTTOM, fill='x')
    h.config(command=messagelist.xview)
    exit_button = Button(window, text="close",height=1, width=6, fg = "green", command=window.destroy).place(x=433, y=352)
    return
    window.mainloop()


def print_message(msg):
    messagelist.insert(tk.END, str(msg))

        

def Send():
    msg = messageinput.get(1.0, "end-1c")
    messageinput.delete('1.0', tk.END)
    print_message("You : " + msg)    
    send_on_port(msg)

#Socket Creation
Connected = False


# Top level window
windoww = tk.Tk()
windoww.title("Al-Fast chat service (Client)")
windoww.geometry('650x550')

UserMessage1 = tk.Label(windoww, text = "Enter Server IP:")
UserMessage1.place(x=10, y=20)

portinput = tk.Text(windoww,height = 1, width = 22)
portinput.place(x=130, y=20)

style = tkk.Style()
style2 = tkk.Style()
 
style.configure('TButton', font =
               ('calibri', 11, 'bold'),
                    borderwidth = '3')

style.map('TButton', foreground = [('active', '!disabled', 'green')],
                     background = [('active', 'black')])


#For Connecting to Server

ListenButton = tkk.Button(windoww, text = "Connect", command=Connect)
ListenButton.place(x=130, y=45)

iplabel = tk.Label(windoww, text = "")
iplabel.place(x=50, y=40)


#For Disconnecting 
MessageButton = tkk.Button(windoww, text = "Disconnect", command = disconnect)
MessageButton.place(x=220, y=45)

#Radio Button to choose encryption 
UC = tk.Label(windoww, text = "Encryption:").place(x=10, y=70)
var = IntVar()
R1 = tk.Radiobutton(windoww, text="AES_CFB", variable=var, value=1).place(x=10, y=90)
R2 = tk.Radiobutton(windoww, text="AES_CBC", variable=var, value=2).place(x=10, y=110)


#To print messages on the scrollbar
UserMessage2 = tk.Label(windoww, text = "Your Chat With The Server :")
UserMessage2.place(x=10, y=145)

scrollbar = tk.Scrollbar(windoww)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
messagelist = tk.Listbox(windoww, yscrollcommand = scrollbar.set, width = 98, height = 20)
messagelist.place(x=10, y=170)

scrollbar.config( command = messagelist.yview )

#To take message as input
MessageButton = tk.Button(windoww, text = "Send", command = Send, width = 10)
MessageButton.place(x=430, y=450)

messageinput = tk.Text(windoww,height = 3,width = 50)
messageinput.place(x=10, y=450)

MessageButton = tk.Button(windoww, text = "Clear", command=clearlist, width = 10)
MessageButton.place(x=520, y=450)

windoww.mainloop()

disconnect(end=True)