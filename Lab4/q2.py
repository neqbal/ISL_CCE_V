import random
import json
import os
from datetime import datetime, timedelta
from sympy import isprime


KEY_DIRECTORY = '/mnt/B2B4A378B4A33E2B/IS/key' 


KEY_EXPIRY_INTERVAL = timedelta(days=365)


if not os.path.exists(KEY_DIRECTORY):
    os.makedirs(KEY_DIRECTORY)

def generate_large_prime(bits):
    while True:
        
        p = random.getrandbits(bits)
        
        if isprime(p):
            return p  

def rabin_key_pair(bits):
    
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    n = p * q  
    public_key = n  
    private_key = (p, q)  
    
    return public_key, private_key  

def encrypt_rabin(public_key, plaintext):
    n = public_key  
    
    return (plaintext ** 2) % n

def decrypt_rabin(private_key, ciphertext):
    p, q = private_key  
    n = p * q  
    
    sqrt_p1 = pow(ciphertext, (p + 1) // 4, p)
    sqrt_p2 = (p - sqrt_p1) % p
    sqrt_q1 = pow(ciphertext, (q + 1) // 4, q)
    sqrt_q2 = (q - sqrt_q1) % q
    
    plaintext_candidates = [
        (sqrt_p1 * sqrt_q1) % n,
        (sqrt_p1 * sqrt_q2) % n,
        (sqrt_p2 * sqrt_q1) % n,
        (sqrt_p2 * sqrt_q2) % n
    ]
    
    return plaintext_candidates  

class KeyManager:
    def __init__(self):
        self.keys = {}  
        self.load_keys()  
    
    def generate_key_pair(self, facility_id, bits=1024):
        public_key, private_key = rabin_key_pair(bits)  
        
        self.keys[facility_id] = {
            'public_key': public_key,
            'private_key': private_key,
            'creation_date': datetime.now().isoformat(),
            'expiry_date': (datetime.now() + KEY_EXPIRY_INTERVAL).isoformat()
        }
        self.save_keys()  
        
        self.audit_log('Key Generation', f"Generated key pair for facility {facility_id}")
        return public_key, private_key  

    def get_key_pair(self, facility_id):
        key_data = self.keys.get(facility_id)  
        
        if key_data and datetime.now() < datetime.fromisoformat(key_data['expiry_date']):
            return key_data['public_key'], key_data['private_key']  
        else:
            raise ValueError("Key not found or expired")  
    
    def revoke_key(self, facility_id):
        if facility_id in self.keys:
            del self.keys[facility_id]  
            self.save_keys()  
            
            self.audit_log('Key Revocation', f"Revoked key pair for facility {facility_id}")
        else:
            raise ValueError("Key not found")  
    
    def renew_keys(self):
        for facility_id, key_data in list(self.keys.items()):
            
            if datetime.now() >= datetime.fromisoformat(key_data['expiry_date']):
                self.generate_key_pair(facility_id)  
                
                self.audit_log('Key Renewal', f"Renewed key pair for facility {facility_id}")
    
    def save_keys(self):
        with open(os.path.join(KEY_DIRECTORY, 'keys.json'), 'w') as f:
            json.dump(self.keys, f, indent=4)  
    
    def load_keys(self):
        key_file = os.path.join(KEY_DIRECTORY, 'keys.json')  
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                self.keys = json.load(f)  
    
    def audit_log(self, action, details):
        
        with open(os.path.join(KEY_DIRECTORY, 'audit.log'), 'a') as f:
            f.write(f"{datetime.now()} - {action}: {details}\n")


if __name__ == "__main__":
    key_manager = KeyManager()  
    
    facility_id = 'hospital_123'  
    
    public_key, private_key = key_manager.generate_key_pair(facility_id)
    print(f"Generated keys for {facility_id}:")
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    
    pub_key, priv_key = key_manager.get_key_pair(facility_id)  
    plaintext = 12345  
    
    encrypted = encrypt_rabin(pub_key, plaintext)
    print(f"Encrypted: {encrypted}")
    
    
    decrypted_candidates = decrypt_rabin(priv_key, encrypted)
    print(f"Decrypted candidates: {decrypted_candidates}")
    
    for pt in decrypted_candidates:
        if pt == plaintext:
            decrypted_plaintext = pt
            break
        else:
            decrypted_plaintext = None
    
    if decrypted_plaintext is not None:
        print(f"Decrypted to original plaintext: {decrypted_plaintext}")
    else:
        print("Decryption did not yield the original plaintext.")

    
    key_manager.renew_keys()

    
    key_manager.revoke_key(facility_id)

    print("Keys after revocation:")
    print(key_manager.keys)
