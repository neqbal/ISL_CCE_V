import socket
import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from phe import paillier
import pickle

class PaymentGatewayServer:
    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Generate Paillier key pair
        print("Generating Paillier keys...")
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        
        # Generate RSA key pair for digital signatures
        print("Generating RSA keys...")
        self.rsa_key = RSA.generate(2048)
        self.rsa_public_key = self.rsa_key.publickey()
        
        self.all_transactions = []
        
    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"\n{'='*80}")
        print(f"Payment Gateway Server Started on {self.host}:{self.port}")
        print(f"{'='*80}\n")
        
        try:
            while True:
                client_socket, address = self.socket.accept()
                print(f"\nConnection from {address}")
                self.handle_client(client_socket)
        except KeyboardInterrupt:
            print("\n\nServer shutting down...")
            self.socket.close()
    
    def handle_client(self, client_socket):
        try:
            # Send public keys to client
            keys_data = {
                'paillier_public_key': {
                    'n': self.public_key.n
                },
                'rsa_public_key': self.rsa_public_key.export_key().decode('utf-8')
            }
            client_socket.send(json.dumps(keys_data).encode('utf-8'))
            
            # Receive encrypted transactions from client
            data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"END_OF_DATA" in data:
                    data = data.replace(b"END_OF_DATA", b"")
                    break
            
            if data:
                transaction_data = pickle.loads(data)
                self.process_transactions(transaction_data)
                
                # Send confirmation
                response = {"status": "success", "message": "Transactions processed"}
                client_socket.send(json.dumps(response).encode('utf-8'))
                
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def process_transactions(self, transaction_data):
        seller_name = transaction_data['seller_name']
        encrypted_amounts = transaction_data['encrypted_amounts']
        transaction_amounts = transaction_data['transaction_amounts']
        
        print(f"\n{'='*80}")
        print(f"Processing Transactions for: {seller_name}")
        print(f"{'='*80}")
        
        # Deserialize encrypted amounts
        encrypted_values = []
        for enc_data in encrypted_amounts:
            encrypted_number = paillier.EncryptedNumber(self.public_key, enc_data['ciphertext'], enc_data['exponent'])
            encrypted_values.append(encrypted_number)
        
        # Homomorphic addition of encrypted amounts
        total_encrypted = encrypted_values[0]
        for enc_val in encrypted_values[1:]:
            total_encrypted = total_encrypted + enc_val
        
        # Decrypt individual amounts
        decrypted_amounts = [self.private_key.decrypt(enc) for enc in encrypted_values]
        
        # Decrypt total
        total_decrypted = self.private_key.decrypt(total_encrypted)
        
        # Create transaction summary
        transaction_summary = {
            'seller_name': seller_name,
            'individual_amounts': transaction_amounts,
            'encrypted_amounts': [str(enc) for enc in encrypted_values],
            'decrypted_amounts': decrypted_amounts,
            'total_encrypted': str(total_encrypted),
            'total_decrypted': total_decrypted
        }
        
        # Create hash of transaction summary for signing
        summary_string = json.dumps(transaction_summary, sort_keys=True)
        summary_hash = SHA256.new(summary_string.encode('utf-8'))
        
        # Generate digital signature
        signature = pkcs1_15.new(self.rsa_key).sign(summary_hash)
        transaction_summary['signature'] = signature.hex()
        transaction_summary['signature_status'] = "Generated"
        
        # Verify signature
        try:
            pkcs1_15.new(self.rsa_public_key).verify(summary_hash, signature)
            transaction_summary['signature_verification'] = "VERIFIED ✓"
            verification_status = True
        except (ValueError, TypeError):
            transaction_summary['signature_verification'] = "FAILED ✗"
            verification_status = False
        
        # Store transaction
        self.all_transactions.append(transaction_summary)
        
        # Display transaction summary
        self.display_transaction_summary(transaction_summary)
        
        # Display all transactions summary
        if len(self.all_transactions) >= 2:
            self.display_all_transactions_summary()
    
    def display_transaction_summary(self, summary):
        print(f"\n{'─'*80}")
        print(f"TRANSACTION SUMMARY - {summary['seller_name']}")
        print(f"{'─'*80}")
        
        print(f"\n📊 Individual Transaction Amounts:")
        for i, amount in enumerate(summary['individual_amounts'], 1):
            print(f"   Transaction {i}: ${amount:,.2f}")
        
        print(f"\n🔒 Encrypted Transaction Amounts:")
        for i, enc_amount in enumerate(summary['encrypted_amounts'], 1):
            print(f"   Encrypted {i}: {enc_amount[:80]}...")
        
        print(f"\n🔓 Decrypted Transaction Amounts:")
        for i, dec_amount in enumerate(summary['decrypted_amounts'], 1):
            print(f"   Decrypted {i}: ${dec_amount:,.2f}")
        
        print(f"\n💰 Total Encrypted Amount:")
        print(f"   {summary['total_encrypted'][:80]}...")
        
        print(f"\n💵 Total Decrypted Amount: ${summary['total_decrypted']:,.2f}")
        
        print(f"\n✍️  Digital Signature Status: {summary['signature_status']}")
        print(f"   Signature (first 64 chars): {summary['signature'][:64]}...")
        
        print(f"\n✅ Signature Verification: {summary['signature_verification']}")
        print(f"{'─'*80}\n")
    
    def display_all_transactions_summary(self):
        print(f"\n{'='*80}")
        print(f"COMPLETE TRANSACTION SUMMARY - ALL SELLERS")
        print(f"{'='*80}\n")
        
        grand_total = 0
        
        for idx, summary in enumerate(self.all_transactions, 1):
            print(f"\n{idx}. Seller: {summary['seller_name']}")
            print(f"   {'─'*70}")
            
            print(f"   Individual Amounts: ", end="")
            print(", ".join([f"${amt:,.2f}" for amt in summary['individual_amounts']]))
            
            print(f"   Decrypted Amounts:  ", end="")
            print(", ".join([f"${amt:,.2f}" for amt in summary['decrypted_amounts']]))
            
            print(f"   Total Amount: ${summary['total_decrypted']:,.2f}")
            print(f"   Signature Status: {summary['signature_status']}")
            print(f"   Verification: {summary['signature_verification']}")
            
            grand_total += summary['total_decrypted']
        
        print(f"\n{'='*80}")
        print(f"GRAND TOTAL (All Sellers): ${grand_total:,.2f}")
        print(f"{'='*80}\n")

if __name__ == "__main__":
    server = PaymentGatewayServer()
    server.start()
