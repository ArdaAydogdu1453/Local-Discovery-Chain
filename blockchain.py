# -*- coding: utf-8 -*-
import datetime
import hashlib
import json
import requests
import threading
import time
import sys
import sqlite3
import jwt
import bcrypt
from functools import wraps
from flask import Flask, jsonify, request, session
from uuid import uuid4
from urllib.parse import urlparse
from flask_cors import CORS 
from flask_socketio import SocketIO, emit
import secrets

# CONFIGURATION
SECRET_KEY = secrets.token_hex(32)
JWT_EXPIRATION = 3600  # 1 saat

# DATABASE SETUP
def init_database():
    """Veritabanı tablolarını oluştur"""
    conn = sqlite3.connect('blockchain_app.db')
    cursor = conn.cursor()
    
    # Kullanıcılar tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            wallet_address TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')
    
    # Mekanlar tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            location_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            address TEXT,
            latitude REAL,
            longitude REAL,
            owner_id INTEGER,
            image_url TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_verified BOOLEAN DEFAULT 0,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    
    # Rozetler/Başarılar tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS achievements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            achievement_type TEXT,
            achievement_name TEXT,
            earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # İşlem geçmişi (hızlı erişim için)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transaction_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_type TEXT,
            sender TEXT,
            receiver TEXT,
            amount REAL,
            block_index INTEGER,
            timestamp TIMESTAMP,
            details TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[✓] Veritabanı başarıyla oluşturuldu")

# JWT AUTHENTICATION
def token_required(f):
    """JWT token kontrolü decorator'ı"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token gerekli!', 'authenticated': False}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_data = data
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token süresi dolmuş!', 'authenticated': False}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Geçersiz token!', 'authenticated': False}), 401
        
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """Admin kontrolü decorator'ı"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.user_data.get('is_admin', False):
            return jsonify({'message': 'Admin yetkisi gerekli!'}), 403
        return f(*args, **kwargs)
    return decorated

# BLOCKCHAIN CLASS (Enhanced)
class AdvancedBlockchain:
    def __init__(self):
        self.chain = []
        self.transactions = [] 
        self.nodes = set()
        self.smart_contracts = {}  # Akıllı sözleşmeler
        
        if not self.load_chain():
            self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        """Yeni blok oluştur ve cache'e kaydet"""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }
        
        # Transaction cache'e kaydet
        self._cache_transactions(block)
        
        self.transactions = [] 
        self.chain.append(block)
        self.save_chain()
        
        # Akıllı sözleşmeleri kontrol et
        self._execute_smart_contracts(block)
        
        return block

    def _cache_transactions(self, block):
        """İşlemleri veritabanına cache'le"""
        conn = sqlite3.connect('blockchain_app.db')
        cursor = conn.cursor()
        
        for tx in block['transactions']:
            cursor.execute('''
                INSERT INTO transaction_cache 
                (transaction_type, sender, receiver, amount, block_index, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                tx.get('type', 'unknown'),
                tx.get('sender', '0'),
                tx.get('receiver', '0'),
                tx.get('amount', 0),
                block['index'],
                block['timestamp'],
                json.dumps(tx)
            ))
        
        conn.commit()
        conn.close()

    def _execute_smart_contracts(self, block):
        """Akıllı sözleşmeleri çalıştır"""
        for tx in block['transactions']:
            # Örnek: Her 10. yorum için bonus puan
            if tx.get('type') == 'comment':
                user_id = tx.get('user_id')
                comment_count = self.get_user_comment_count(user_id)
                
                if comment_count % 10 == 0 and comment_count > 0:
                    bonus_tx = {
                        'type': 'bonus',
                        'sender': 'SMART_CONTRACT',
                        'receiver': user_id,
                        'amount': 5,
                        'reason': f'{comment_count}. yorum bonusu'
                    }
                    self.add_transaction(bonus_tx)

    def get_user_comment_count(self, user_id):
        """Kullanıcının toplam yorum sayısı"""
        count = 0
        for block in self.chain:
            for tx in block['transactions']:
                if tx.get('type') == 'comment' and tx.get('user_id') == user_id:
                    count += 1
        return count

    def get_previous_block(self):
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()
            ).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        if not chain:
            return False
            
        previous_block = chain[0]
        block_index = 1
        
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()
            ).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
    
    def add_transaction(self, data):
        """Transaction ekle ve validasyon yap"""
        if data.get('type') == 'transfer':
            sender = data.get('sender')
            amount = data.get('amount', 0)
            
            if amount <= 0:
                return {'success': False, 'message': 'Miktar pozitif olmalıdır'}
            
            balance = self.get_balance(sender)
            if balance < amount:
                return {
                    'success': False, 
                    'message': f'Yetersiz bakiye! Mevcut: {balance}, Gerekli: {amount}'
                }
        
        self.transactions.append(data)
        previous_block = self.get_previous_block()
        return {
            'success': True, 
            'block_index': previous_block['index'] + 1 if previous_block else 1
        }
    
    def get_balance(self, user_id):
        """Kullanıcının toplam bakiyesini hesapla (cache'ten)"""
        conn = sqlite3.connect('blockchain_app.db')
        cursor = conn.cursor()
        
        # Gelen işlemler
        cursor.execute('''
            SELECT COALESCE(SUM(amount), 0) FROM transaction_cache 
            WHERE receiver = ? AND transaction_type IN ('reward', 'transfer', 'bonus')
        ''', (user_id,))
        incoming = cursor.fetchone()[0]
        
        # Giden işlemler
        cursor.execute('''
            SELECT COALESCE(SUM(amount), 0) FROM transaction_cache 
            WHERE sender = ? AND transaction_type = 'transfer'
        ''', (user_id,))
        outgoing = cursor.fetchone()[0]
        
        conn.close()
        return incoming - outgoing
    
    def get_leaderboard(self, limit=10):
        """Lider tablosu"""
        conn = sqlite3.connect('blockchain_app.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT receiver, SUM(amount) as total_points
            FROM transaction_cache
            WHERE transaction_type IN ('reward', 'transfer', 'bonus')
            GROUP BY receiver
            ORDER BY total_points DESC
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return [{'user_id': row[0], 'points': row[1], 'rank': idx + 1} 
                for idx, row in enumerate(results)]
    
    def get_location_stats(self, location_id):
        """Mekan istatistikleri"""
        ratings = []
        comments = []
        users = set()
        
        for block in self.chain:
            for transaction in block['transactions']:
                if (transaction.get('type') == 'comment' and 
                    transaction.get('location_id') == location_id):
                    ratings.append(transaction.get('rating', 0))
                    users.add(transaction.get('user_id'))
                    comments.append({
                        'user': transaction.get('user_id'),
                        'rating': transaction.get('rating'),
                        'text': transaction.get('comment_text'),
                        'block': block['index'],
                        'time': block['timestamp']
                    })
        
        return {
            'total_comments': len(ratings),
            'unique_users': len(users),
            'average_rating': sum(ratings) / len(ratings) if ratings else 0,
            'rating_distribution': {
                '5_star': ratings.count(5),
                '4_star': ratings.count(4),
                '3_star': ratings.count(3),
                '2_star': ratings.count(2),
                '1_star': ratings.count(1)
            },
            'comments': comments
        }
    
    def get_user_activity(self, user_id):
        """Kullanıcı aktivite özeti"""
        conn = sqlite3.connect('blockchain_app.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT transaction_type, COUNT(*) 
            FROM transaction_cache 
            WHERE sender = ? OR receiver = ?
            GROUP BY transaction_type
        ''', (user_id, user_id))
        
        activity = dict(cursor.fetchall())
        conn.close()
        
        return {
            'user_id': user_id,
            'balance': self.get_balance(user_id),
            'total_comments': activity.get('comment', 0),
            'transfers_sent': activity.get('transfer', 0),
            'rewards_earned': activity.get('reward', 0) + activity.get('bonus', 0)
        }
    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)

        for node in network:
            try:
                response = requests.get(f'http://{node}/get_chain', timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    length = data['length']
                    chain = data['chain']

                    if length > max_length and self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
                        
            except:
                continue

        if longest_chain:
            self.chain = longest_chain
            self.save_chain() 
            return True 
        
        return False 
    
    def save_chain(self):
        data = {
            'chain': self.chain,
            'transactions': self.transactions,
            'nodes': list(self.nodes) 
        }
        try:
            with open('blockchain_data.json', 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False) 
            return True
        except Exception as e:
            print(f"[HATA] Zincir kaydedilirken hata: {e}")
            return False

    def load_chain(self):
        try:
            with open('blockchain_data.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.chain = data.get('chain', [])
                self.transactions = data.get('transactions', [])
                self.nodes = set(data.get('nodes', []))
                return True
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"[HATA] Blockchain verileri yüklenirken: {e}")
            return False


# FLASK APP
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading') 

# Initialize
init_database()
node_address = str(uuid4()).replace('-', '')
MINER_USER_ID = "MINER_" + node_address[:8]
blockchain = AdvancedBlockchain()

# ==================== AUTH ENDPOINTS ====================

@app.route('/auth/register', methods=['POST'])
def register():
    """Kullanıcı kaydı"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'message': 'Tüm alanlar gerekli'}), 400
        
        if len(password) < 6:
            return jsonify({'message': 'Şifre en az 6 karakter olmalı'}), 400
        
        # Wallet adresi oluştur
        wallet_address = f"0x{hashlib.sha256(username.encode()).hexdigest()[:40]}"
        
        # Şifreyi hashle
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = sqlite3.connect('blockchain_app.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, wallet_address)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, wallet_address))
            conn.commit()
            user_id = cursor.lastrowid
            
            # Hoş geldin bonusu
            bonus_tx = {
                'type': 'bonus',
                'sender': 'SYSTEM',
                'receiver': username,
                'amount': 10,
                'reason': 'Hoş geldin bonusu'
            }
            blockchain.add_transaction(bonus_tx)
            
            conn.close()
            
            return jsonify({
                'message': 'Kayıt başarılı! 10 puan hediye edildi.',
                'user_id': user_id,
                'wallet_address': wallet_address
            }), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'message': 'Kullanıcı adı veya email zaten kullanımda'}), 400
            
    except Exception as e:
        return jsonify({'message': f'Hata: {str(e)}'}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    """Kullanıcı girişi"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'message': 'Kullanıcı adı ve şifre gerekli'}), 400
        
        conn = sqlite3.connect('blockchain_app.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, password_hash, wallet_address, is_admin 
            FROM users WHERE username = ? AND is_active = 1
        ''', (username,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'message': 'Kullanıcı bulunamadı'}), 404
        
        # Şifre kontrolü
        if not bcrypt.checkpw(password.encode('utf-8'), user[3]):
            return jsonify({'message': 'Hatalı şifre'}), 401
        
        # JWT token oluştur
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'wallet_address': user[4],
            'is_admin': bool(user[5]),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXPIRATION)
        }, SECRET_KEY, algorithm="HS256")
        
        return jsonify({
            'message': 'Giriş başarılı',
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'wallet_address': user[4],
                'is_admin': bool(user[5])
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Hata: {str(e)}'}), 500

@app.route('/auth/verify', methods=['GET'])
@token_required
def verify_token():
    """Token doğrulama"""
    return jsonify({
        'authenticated': True,
        'user': request.user_data
    }), 200

# ==================== LOCATION ENDPOINTS ====================

@app.route('/locations/create', methods=['POST'])
@token_required
def create_location():
    """Yeni mekan ekle"""
    try:
        data = request.get_json()
        location_id = data.get('location_id', '').strip()
        name = data.get('name', '').strip()
        category = data.get('category', '')
        address = data.get('address', '')
        
        if not location_id or not name:
            return jsonify({'message': 'Mekan ID ve isim gerekli'}), 400
        
        conn = sqlite3.connect('blockchain_app.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO locations 
                (location_id, name, category, address, owner_id, latitude, longitude, image_url, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                location_id, name, category, address, 
                request.user_data['user_id'],
                data.get('latitude'),
                data.get('longitude'),
                data.get('image_url'),
                data.get('description')
            ))
            conn.commit()
            conn.close()
            
            return jsonify({'message': 'Mekan başarıyla eklendi', 'location_id': location_id}), 201
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'message': 'Bu mekan ID zaten kullanımda'}), 400
            
    except Exception as e:
        return jsonify({'message': f'Hata: {str(e)}'}), 500

@app.route('/locations/list', methods=['GET'])
def list_locations():
    """Tüm mekanları listele"""
    conn = sqlite3.connect('blockchain_app.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT location_id, name, category, address, image_url, description, is_verified
        FROM locations ORDER BY created_at DESC
    ''')
    
    locations = []
    for row in cursor.fetchall():
        locations.append({
            'location_id': row[0],
            'name': row[1],
            'category': row[2],
            'address': row[3],
            'image_url': row[4],
            'description': row[5],
            'is_verified': bool(row[6])
        })
    
    conn.close()
    return jsonify({'locations': locations, 'count': len(locations)}), 200

# ==================== BLOCKCHAIN ENDPOINTS ====================

@app.route('/blockchain/add_comment', methods=['POST'])
@token_required
def add_comment():
    """Yorum ekle (authenticated)"""
    try:
        data = request.get_json()
        location_id = data.get('location_id', '').strip()
        rating = data.get('rating')
        comment_text = data.get('comment_text', '').strip()
        
        if not location_id or not rating or not comment_text:
            return jsonify({'message': 'Tüm alanlar gerekli'}), 400
        
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify({'message': 'Puan 1-5 arasında olmalı'}), 400
        
        comment_data = {
            'type': 'comment',
            'user_id': request.user_data['username'],
            'wallet_address': request.user_data['wallet_address'],
            'location_id': location_id,
            'rating': rating,
            'comment_text': comment_text
        }
        
        result = blockchain.add_transaction(comment_data)
        
        if result.get('success'):
            return jsonify({
                'message': 'Yorum başarıyla eklendi!',
                'block_index': result['block_index']
            }), 201
        else:
            return jsonify({'message': result.get('message')}), 400
            
    except Exception as e:
        return jsonify({'message': f'Hata: {str(e)}'}), 500

@app.route('/blockchain/transfer', methods=['POST'])
@token_required
def transfer_points():
    """Puan transferi (authenticated)"""
    try:
        data = request.get_json()
        receiver = data.get('receiver', '').strip()
        amount = data.get('amount')
        
        if not receiver or not amount:
            return jsonify({'message': 'Alıcı ve miktar gerekli'}), 400
        
        if amount <= 0:
            return jsonify({'message': 'Miktar pozitif olmalı'}), 400
        
        transaction_data = {
            'type': 'transfer',
            'sender': request.user_data['username'],
            'receiver': receiver,
            'amount': amount
        }
        
        result = blockchain.add_transaction(transaction_data)
        
        if result.get('success'):
            return jsonify({
                'message': 'Transfer başarılı!',
                'block_index': result['block_index'],
                'new_balance': blockchain.get_balance(request.user_data['username'])
            }), 201
        else:
            return jsonify({'message': result.get('message')}), 400
            
    except Exception as e:
        return jsonify({'message': f'Hata: {str(e)}'}), 500

@app.route('/blockchain/balance/<username>', methods=['GET'])
def get_balance(username):
    """Bakiye sorgula"""
    balance = blockchain.get_balance(username)
    return jsonify({'username': username, 'balance': balance}), 200

@app.route('/blockchain/activity/<username>', methods=['GET'])
def get_activity(username):
    """Kullanıcı aktivitesi"""
    activity = blockchain.get_user_activity(username)
    return jsonify(activity), 200

@app.route('/blockchain/leaderboard', methods=['GET'])
def get_leaderboard():
    """Lider tablosu"""
    limit = request.args.get('limit', 10, type=int)
    leaderboard = blockchain.get_leaderboard(limit)
    return jsonify({'leaderboard': leaderboard}), 200

@app.route('/blockchain/location_stats/<location_id>', methods=['GET'])
def get_location_stats(location_id):
    """Mekan istatistikleri"""
    stats = blockchain.get_location_stats(location_id)
    return jsonify(stats), 200

@app.route('/blockchain/chain', methods=['GET'])
def get_chain():
    """Tüm zinciri getir"""
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }), 200

# ==================== ADMIN ENDPOINTS ====================

@app.route('/admin/users', methods=['GET'])
@token_required
@admin_required
def admin_get_users():
    """Tüm kullanıcıları listele (admin only)"""
    conn = sqlite3.connect('blockchain_app.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, email, wallet_address, created_at, is_active 
        FROM users ORDER BY created_at DESC
    ''')
    
    users = []
    for row in cursor.fetchall():
        users.append({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'wallet_address': row[3],
            'created_at': row[4],
            'is_active': bool(row[5]),
            'balance': blockchain.get_balance(row[1])
        })
    
    conn.close()
    return jsonify({'users': users, 'count': len(users)}), 200

@app.route('/admin/verify_location/<location_id>', methods=['POST'])
@token_required
@admin_required
def verify_location(location_id):
    """Mekanı onayla (admin only)"""
    conn = sqlite3.connect('blockchain_app.db')
    cursor = conn.cursor()
    
    cursor.execute('UPDATE locations SET is_verified = 1 WHERE location_id = ?', (location_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': f'{location_id} onaylandı'}), 200

# ==================== BACKGROUND MINING ====================

def auto_mine_and_sync():
    """Arka planda madencilik"""
    time.sleep(15)
    
    while True:
        try:
            if len(blockchain.nodes) > 0:
                blockchain.replace_chain()

            if blockchain.transactions:
                previous_block = blockchain.get_previous_block()
                
                if previous_block:
                    previous_proof = previous_block['proof']
                    proof = blockchain.proof_of_work(previous_proof)
                    previous_hash = blockchain.hash(previous_block)
                    
                    reward_data = {
                        "type": "reward", 
                        "sender": "0", 
                        "receiver": MINER_USER_ID, 
                        "amount": 1
                    }
                    blockchain.add_transaction(reward_data)
                    
                    block = blockchain.create_block(proof, previous_hash)
                    
                    socketio.emit('new_block', {
                        'message': 'Yeni blok kazıldı!', 
                        'index': block['index']
                    })
                    
                    print(f"\n[AUTO-MINE] Blok #{block['index']} | İşlem: {len(block['transactions'])}")
            
            time.sleep(60)
            
        except Exception as e:
            print(f"[HATA] Otomatik madencilik: {e}")
            time.sleep(60)

if __name__ == '__main__':
    port = 5000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    
    miner_thread = threading.Thread(target=auto_mine_and_sync, daemon=True) 
    miner_thread.start()
    
    print("=" * 70)
    print("| YEREL KEŞİF ZİNCİRİ - PRODUCTION VERSION                         |")
    print("=" * 70)
    print(f"| Port: {port}                                                        |")
    print(f"| Madenci: {MINER_USER_ID}                              |")
    print("| Database: blockchain_app.db (SQLite)                             |")
    print("| Features: JWT Auth, Wallet, Leaderboard, Smart Contracts        |")
    print("=" * 70)
    print("\n[✓] Sistem hazır. API dokümantasyonu için /docs endpoint'ini ziyaret edin.\n")
    
    try:
        socketio.run(app, host='0.0.0.0', port=port, debug=False) 
    except Exception as e:
        print(f"\n[KRİTİK HATA] Sunucu başlatılamadı: {e}")