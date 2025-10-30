import socket
import json
import time
from phe import paillier
import pickle

class SellerClient:
    def __init__(self, seller_name, transactions, host='localhost', port=9999):
        self.seller_name = seller_name
        self.transactions = transactions
        self.host = host
        self.port = port
        self.public_key = None
        
    def connect_and_send(self):
        try:
            # Connect to server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            print(f"\n{'='*80}")
            print(f"Connected to Payment Gateway Server")
            print(f"Seller: {self.seller_name}")
            print(f"{'='*80}\n")
            
            # Receive public keys from server
            keys_data = json.loads(client_socket.recv(4096).decode('utf-8'))
            
            # Reconstruct Paillier public key
            n = keys_data['paillier_public_key']['n']
            self.public_key = paillier.PaillierPublicKey(n)
            
            print(f"✓ Received Paillier Public Key")
            print(f"✓ Received RSA Public Key\n")
            
            # Encrypt transactions
            print(f"Processing {len(self.transactions)} transactions...\n")
            encrypted_amounts = []
            
            for i, amount in enumerate(self.transactions, 1):
                print(f"Transaction {i}:")
                print(f"  Original Amount: ${amount:,.2f}")
                
                # Encrypt using Paillier
                encrypted = self.public_key.encrypt(amount)
                encrypted_amounts.append(encrypted)
                
                print(f"  Encrypted: {str(encrypted.ciphertext())[:80]}...")
                print()
            
            # Serialize encrypted amounts
            serialized_encrypted = []
            for enc in encrypted_amounts:
                serialized_encrypted.append({
                    'ciphertext': enc.ciphertext(),
                    'exponent': enc.exponent
                })
            
            # Prepare transaction data
            transaction_data = {
                'seller_name': self.seller_name,
                'transaction_amounts': self.transactions,
                'encrypted_amounts': serialized_encrypted
            }
            
            # Send encrypted transactions to server
            print(f"📤 Sending encrypted transactions to Payment Gateway...")
            data_to_send = pickle.dumps(transaction_data)
            client_socket.sendall(data_to_send + b"END_OF_DATA")
            
            # Receive confirmation
            response = json.loads(client_socket.recv(1024).decode('utf-8'))
            print(f"✓ Server Response: {response['message']}\n")
            
            client_socket.close()
            
        except Exception as e:
            print(f"Error: {e}")

def main():
    # Define sellers and their transactions
    sellers = [
        {
            'name': 'TechStore Electronics',
            'transactions': [1500.00, 2300.50, 850.75]
        },
        {
            'name': 'Fashion Boutique',
            'transactions': [450.00, 780.25, 320.50, 1100.00]
        },
        {
            'name': 'BookWorld Online',
            'transactions': [89.99, 125.50]
        }
    ]
    
    print("\n" + "="*80)
    print("PAYMENT GATEWAY TRANSACTION SYSTEM")
    print("Client Application - Multiple Sellers")
    print("="*80)
    
    # Send transactions from each seller
    for seller in sellers:
        client = SellerClient(seller['name'], seller['transactions'])
        client.connect_and_send()
        time.sleep(1)  # Small delay between sellers
    
    print("\n" + "="*80)
    print("All transactions sent successfully!")
    print("Check server console for complete transaction summary")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
