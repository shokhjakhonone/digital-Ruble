import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import datetime

# AES-256 Encryption/Decryption Helper Class
class AESEncryption:
    def _init_(self, key):
        self.key = key
    
    def encrypt(self, data):
        iv = os.urandom(16)  # Генерируем случайный IV
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data.encode()) + encryptor.finalize()

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:16]  # Извлекаем IV
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data[16:]).decode() + decryptor.finalize().decode()

# Хэширование данных с использованием SHA-256
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Пользовательский класс с шифрованием баланса
class User:
    def _init_(self, name, initial_balance=0, encryption_key=None):
        self.name = name
        self.encryption_key = encryption_key
        self.encrypted_balance = None
        self.aes_cipher = AESEncryption(encryption_key)
        self.set_balance(initial_balance)
        self.transaction_history = []
    
    def set_balance(self, balance):
        # Шифруем баланс с использованием AES-256
        self.encrypted_balance = self.aes_cipher.encrypt(str(balance))
    
    def get_balance(self):
        # Дешифруем баланс с использованием AES-256
        decrypted_balance = self.aes_cipher.decrypt(self.encrypted_balance)
        return int(decrypted_balance)

    def deposit(self, amount):
        if amount > 0:
            balance = self.get_balance() + amount
            self.set_balance(balance)
            self.add_transaction('deposit', amount)
            print(f"{self.name} deposited {amount} digital rubles. New balance: {balance} digital rubles.")
        else:
            print("Deposit amount must be positive.")
    
    def withdraw(self, amount):
        balance = self.get_balance()
        if 0 < amount <= balance:
            balance -= amount
            self.set_balance(balance)
            self.add_transaction('withdraw', amount)
            print(f"{self.name} withdrew {amount} digital rubles. Remaining balance: {balance} digital rubles.")
        else:
            print("Insufficient funds or invalid amount.")
    
    def transfer(self, amount, recipient):
        balance = self.get_balance()
        if 0 < amount <= balance:
            recipient_balance = recipient.get_balance()
            self.set_balance(balance - amount)
            recipient.set_balance(recipient_balance + amount)
            self.add_transaction('transfer to ' + recipient.name, amount)
            recipient.add_transaction('transfer from ' + self.name, amount)
            print(f"{self.name} transferred {amount} digital rubles to {recipient.name}.")
        else:
            print("Insufficient funds or invalid amount.")

    def add_transaction(self, transaction_type, amount):
        timestamp = datetime.datetime.now()
        transaction_record = {
            'type': transaction_type,
            'amount': amount,
            'timestamp': timestamp,
            'balance': self.get_balance()
        }
        self.transaction_history.append(transaction_record)

    def print_transaction_history(self):
        print(f"\nTransaction history for {self.name}:")
        for tx in self.transaction_history:
            print(f"{tx['timestamp']} | {tx['type']} | {tx['amount']} digital rubles | Balance: {tx['balance']}")
    
# Blockchain class remains the same as before
class DigitalRubleBlockchain:
    def _init_(self):
        self.chain = []
    
    def create_genesis_block(self):
        genesis_block = {
            'index': 0,
            'timestamp': datetime.datetime.now(),
            'transactions': [],
            'previous_hash': "0",
            'hash': self.hash_block(0, datetime.datetime.now(), [], "0")
        }
        self.chain.append(genesis_block)
    
    def add_block(self, transactions):
        previous_block = self.chain[-1]
        new_block_index = previous_block['index'] + 1
        new_block_timestamp = datetime.datetime.now()
        new_block_previous_hash = previous_block['hash']
        new_block_hash = self.hash_block(new_block_index, new_block_timestamp, transactions, new_block_previous_hash)
        new_block = {
            'index': new_block_index,
            'timestamp': new_block_timestamp,
            'transactions': transactions,
            'previous_hash': new_block_previous_hash,
            'hash': new_block_hash
        }
        self.chain.append(new_block)
    
    def hash_block(self, index, timestamp, transactions, previous_hash):
        block_contents = f"{index}{timestamp}{transactions}{previous_hash}".encode()
        return hashlib.sha256(block_contents).hexdigest()
    
    def display_chain(self):
        for block in self.chain:
            print(f"Block {block['index']} | Hash: {block['hash']} | Previous Hash: {block['previous_hash']}")
            print(f"Transactions: {block['transactions']}\n")

# Генерация 256-битного ключа для AES (32 байта)
aes_key = os.urandom(32)

# Создаем блокчейн и пользователей
blockchain = DigitalRubleBlockchain()
blockchain.create_genesis_block()

shokh = User('Shokh', 1000, aes_key)
maks = User('Maks', 500, aes_key)

# Пример операций
shokh.deposit(200)
shokh.withdraw(150)
shokh.transfer(300, maks)

# Добавление транзакций в блокчейн
blockchain.add_block(shokh.transaction_history)
blockchain.add_block(maks.transaction_history)

# Печать истории транзакций
shokh.print_transaction_history()
maks.print_transaction_history()

# Печать блокчейна
print("\nBlockchain:")
blockchain.display_chain()
