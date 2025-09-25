import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime
from datetime import datetime, timedelta

KEY_DIRECTORY = "./key"
KEY_EXPIRY = timedelta(days=365)

if not os.path.exists(KEY_DIRECTORY):
    os.makedirs(KEY_DIRECTORY)


class Rabin:
    def __init__(self):
        self.public_key = 0
        self.private_key = 0
        self.p = 0
        self.q = 0

    @classmethod
    def generate(cls, bits=1024):
        obj = cls()

        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
    
        obj.p = p
        obj.q = q
        obj.public_key = p*q
        obj.private_key = (p, q)
        return obj
        
    def encrypt(self, pt):
        return (pt ** 2) % self.public_key
    
    def decrypt(self, ct):
        p, q = self.p, self.q
        n = p*q
        
        a1 = pow(ct, (p+1)//4, p)
        a2 = (p - a1)%p
        b1 = pow(ct, (q+1)//4, q)
        b2 = (q - b1)%q
    
        candidates = [
            (a1*b1)%n,
            (a1*b2)%n,
            (a2*b1)%n,
            (a2*b2)%n
        ]
    
        return candidates

class HealthCare:
    def __init__(self):
        self.facility = {}
        self.log = []
        self.rsa_pub = {}


    def register(self, id, public_key):
        print(public_key)
        print(id)
        rabin = Rabin.generate()
        private = rabin.private_key
        public = rabin.public_key
        
        self.facility[id] = {
            'session_public': public,
            'session_private': private,
            'creation_date': datetime.now().isoformat(),
            'exp_date': (datetime.now() + KEY_EXPIRY).isoformat()
        }

        self.rsa_pub[id] = public_key

        self.log.append(f"{id} Registered, RSA {public_key} stored")


    def request_keys(self, id):
        private = self.facility[id]['session_private']

        rsa_pub = self.rsa_pub[id]

        rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_pub))

        private_p_enc = rsa_cipher.encrypt(private[0].to_bytes((private[0].bit_length() + 7) //8, 'big'))
        private_q_enc = rsa_cipher.encrypt(private[1].to_bytes((private[1].bit_length() + 7) //8, 'big'))

        self.log.append(f"{id} Ephemeral private key sent")

        return (private_p_enc, private_q_enc)

    def displayLog(self):
        print(self.log)

class Facility:
    def __init__(self):
        self.rsa_keys = {}
        self.session_keys = {}
        self.id = ""
        self.log = []
        pass
    
    @classmethod
    def new(cls, id):
        rsa = RSA.generate(2048)

        obj = cls()
        obj.id = id
        obj.rsa_keys = {
            'public': rsa.public_key().export_key(),
            'private': rsa.export_key()
        }

        obj.log.append(f"{id} RSA public and private key generated")
        return obj

    def get_keys(self, hc: HealthCare):
        p_enc, q_enc = hc.request_keys(self.id)
        
        rsa_cipher = PKCS1_OAEP.new(RSA.import_key(self.rsa_keys['private']))
        private_dec = (int.from_bytes(rsa_cipher.decrypt(p_enc), 'big') , int.from_bytes(rsa_cipher.decrypt(q_enc), 'big'))

        self.session_keys = {
            'public': private_dec[0]*private_dec[1],
            'private': private_dec
        }

        self.log.append(f"{self.id} Ephemeral Rabin private keys received")

    def displayLog(self):
        print(self.log)

hc = HealthCare()

hospital_123 = Facility.new("hospital_123")

hc.register(hospital_123.id, hospital_123.rsa_keys["public"])

hospital_123.get_keys(hc)

hc.displayLog()
hospital_123.displayLog()
