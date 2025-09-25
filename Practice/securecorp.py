from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Random import random
from Crypto.Protocol.KDF import HKDF

class SecureCommunicationSystem:
    def __init__(self):
        self.subsystem = {}
        self.log = []

    def createSubsystem(self, subsystem_id):
        rsa = RSA.generate(2048)
        
        self.subsystem[subsystem_id] = {
            "public": rsa.public_key(),
            "private": rsa 
        }

        self.log.append(f"{subsystem_id} added")

    def dh_key_exch(self, sender_id, receiver_id):
        dh = DSA.generate(2048)
        p, g = dh.p, dh.g

        sender_private = random.randint(2, p-2)
        sender_public = pow(g, sender_private, p)

        msg_sender = str(sender_public).encode()
        msg_sender_hash = SHA256.new(msg_sender)
        sender_sign = pkcs1_15.new(self.subsystem[sender_id]["private"]).sign(msg_sender_hash)


        receiver_private = random.randint(2, p-2)
        receiver_public = pow(g, receiver_private, p)

        msg_receiver = str(receiver_public).encode()
        msg_receiver_hash = SHA256.new(msg_receiver)
        receiver_sign = pkcs1_15.new(self.subsystem[receiver_id]["private"]).sign(msg_receiver_hash)

        try:
            pkcs1_15.new(self.subsystem[receiver_id]["public"]).verify(SHA256.new(str(receiver_public).encode()), receiver_sign)
            print(f"{sender_id} verified {receiver_id}'s DH public key'")
        except(ValueError, TypeError):
            print(f"{sender_id} cannot verify {receiver_id}'s DH public key'")
        
        try:
            pkcs1_15.new(self.subsystem[sender_id]["public"]).verify(SHA256.new(str(sender_public).encode()), sender_sign)
            print(f"{receiver_id} verified {sender_id}'s DH public key'")
        except(ValueError, TypeError):
            print(f"{receiver_id} cannot verify {sender_id}'s DH public key'")

        sender_shared_secret = pow(receiver_public, sender_private, p)
        receiver_shared_secret = pow(sender_public, receiver_private, p)

        if sender_shared_secret == receiver_shared_secret:
            shared_key = HKDF(sender_shared_secret.to_bytes((sender_shared_secret.bit_length() + 7)//8 ), 16, b'deadbeefdeadbeef', SHA256)
            self.subsystem[sender_id][receiver_id] = shared_key
            self.subsystem[receiver_id][sender_id] = shared_key
            self.log.append(f"{sender_id} {receiver_id} shared secret generated")

    def encrypt(self, sender_id, receiver_id, message):
        shared_key = self.subsystem[sender_id][receiver_id]

        aes = AES.new(shared_key, AES.MODE_EAX)
        cipher_text, tag = aes.encrypt_and_digest(message.encode())

        self.log.append(f"Message encrypted from {sender_id} to {receiver_id} = {cipher_text}")
        return aes.nonce + tag + cipher_text
    
    def decrypt(self, sender_id, receiver_id, encr):
        shared_key = self.subsystem[receiver_id][sender_id]
        nonce = encr[:16]
        tag = encr[16:32]
        message = encr[32:]
        aes = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
        plain_text = ""
        try:
            plain_text = aes.decrypt_and_verify(message, tag)
            self.log.append(f"Message decrypted from {sender_id} to {receiver_id} = {plain_text}")
        except ValueError:
            self.log.append("Could not decrypt")

        return plain_text
    
    def revoke(self, id):
        del self.subsystem[id]

    def displayLog(self):
        print(self.log)

    def displaySubsystem(self):
        print(self.subsystem)

ss = SecureCommunicationSystem()

ss.createSubsystem("FI")
ss.createSubsystem("HR")
ss.createSubsystem("SC")

ss.dh_key_exch("FI", "HR")
ss.dh_key_exch("FI", "SC")
ss.dh_key_exch("HR", "SC")

encr = ss.encrypt("FI", "SC", "Hello SC from FI")
decr = ss.decrypt("FI", "SC", encr)
print(decr)
ss.displayLog()
