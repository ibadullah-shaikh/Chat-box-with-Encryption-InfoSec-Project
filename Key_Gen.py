from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os

if(os.path.exists('client_private_key.pem') and os.path.exists('client_public_key.pem') ):
   {
    print("client private and public key already exists!!!")
   }
else:
    new_key = RSA.generate(2048)
    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")
    fd = open("client_private_key.pem", "wb")
    fd.write(private_key)
    fd.close()
    fd = open("client_public_key.pem", "wb")
    fd.write(public_key)
    fd.close()
    print("Successfully generated client private and public key!!!")


if(os.path.exists('server_private_key.pem') and os.path.exists('server_public_key.pem') ):
   {
    print("server private and public key already exists!!!")
   }
else:
    new_key = RSA.generate(2048)
    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")
    fd = open("server_private_key.pem", "wb")
    fd.write(private_key)
    fd.close()
    fd = open("server_public_key.pem", "wb")
    fd.write(public_key)
    fd.close()
    print("Successfully generated server private and public key!!!")
'''
new_key = RSA.generate(2048)
private_key = new_key.exportKey("PEM")
public_key = new_key.publickey().exportKey("PEM")
fd = open("client_private_key.pem", "wb")
fd.write(private_key)
fd.close()
fd = open("client_public_key.pem", "wb")
fd.write(public_key)
fd.close()

message =b'TFz6P+az1KEs4BDy9W38ZhXMVHJOUwDpgNKRljkOXjGZ9W82VkZ+5kdM2lH99EfPLRtj0OvU4qDVbSBPjkXwBfZ5CQ1Inb0F_K190362K190307K190174_ae'
print(len(message))

pu_key = RSA.import_key(open('client_public_key.pem').read())
cipher = PKCS1_OAEP.new(pu_key)
ciphertext = cipher.encrypt(message)
print(len(ciphertext))
print("\n\n")


pr_key = RSA.import_key(open('client_private_key.pem').read())
cipher = PKCS1_OAEP.new(pr_key)
plaintext = cipher.decrypt(ciphertext)
print (plaintext.decode("utf-8"))
'''