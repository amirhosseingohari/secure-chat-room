import socket
import ssl
import json
import sqlite3
import hashlib
import os
import threading
import time
import logging

# تنظیمات اصلی سرور
HOST = '127.0.0.1'
PORT = 8443
CERT_DIR = 'certs'
DB_PATH = 'server/chat.db'
LOG_PATH = 'server/server.log'

# پیکربندی سیستم Log-گیری
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ایجاد پایگاه داده و جداول مورد نیاز
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # جدول کاربران
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    
    # جدول پیام‌ها
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # ساخت یک کاربر پیش‌فرض ادمین در صورت عدم وجود
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        salt = os.urandom(16).hex()
        # رمز عبور پیش‌فرض ادمین: admin123
        pwd_hash = hashlib.sha256(("admin123" + salt).encode('utf-8')).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
            ("admin", pwd_hash, salt, "admin")
        )
        logging.info("Default admin user created (admin / admin123)")
        
    conn.commit()
    conn.close()

# مدیریت نشست‌های کاربران آنلاین
online_clients = {}  # {username: ssl_socket}
online_lock = threading.Lock()

# کنترل نرخ ارسال (Anti-Spam Rate Limiting)
# {username: [timestamp1, timestamp2, ...]}
message_timestamps = {}
rate_limit_lock = threading.Lock()
MAX_MSG_PER_WINDOW = 5
WINDOW_SECONDS = 10

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def verify_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        stored_hash, salt = row
        if hash_password(password, salt) == stored_hash:
            return True
    return False

def register_user(username, password, role="user"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        salt = os.urandom(16).hex()
        pwd_hash = hash_password(password, salt)
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
            (username, pwd_hash, salt, role)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def save_message(sender, content):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    cursor.execute(
        "INSERT INTO messages (sender, content, timestamp) VALUES (?, ?, ?)",
        (sender, content, timestamp)
    )
    conn.commit()
    msg_id = cursor.lastrowid
    conn.close()
    return msg_id, timestamp

def get_missed_messages(last_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, sender, content, timestamp FROM messages WHERE id > ? ORDER BY id ASC",
        (last_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    
    missed = []
    for row in rows:
        missed.append({
            "type": "chat",
            "id": row[0],
            "sender": row[1],
            "content": row[2],
            "time": row[3]
        })
    return missed

def is_rate_limited(username):
    with rate_limit_lock:
        now = time.time()
        if username not in message_timestamps:
            message_timestamps[username] = []
        
        # پاک کردن زمان‌های خارج از پنجره زمانی
        message_timestamps[username] = [t for t in message_timestamps[username] if now - t < WINDOW_SECONDS]
        
        if len(message_timestamps[username]) >= MAX_MSG_PER_WINDOW:
            return True
        
        message_timestamps[username].append(now)
        return False

def broadcast(message_dict, exclude_username=None):
    payload = (json.dumps(message_dict) + "\n").encode('utf-8')
    with online_lock:
        for user, sock in list(online_clients.items()):
            if user != exclude_username:
                try:
                    sock.sendall(payload)
                except Exception as e:
                    logging.error(f"Error sending broadcast to {user}: {e}")
                    # در صورت خطا اتصال قطع فرض می‌شود
                    try:
                        sock.close()
                    except:
                        pass
                    online_clients.pop(user, None)

def send_response(sock, response_dict):
    try:
        sock.sendall((json.dumps(response_dict) + "\n").encode('utf-8'))
    except Exception as e:
        logging.error(f"Error sending response: {e}")

# مدیریت ارتباط کلاینت به صورت همزمان
def handle_client(ssl_sock, addr):
    logging.info(f"New TLS connection from {addr}")
    current_user = None
    buffer = ""
    
    try:
        while True:
            # دریافت داده‌ها از سوکت
            data = ssl_sock.recv(4096).decode('utf-8')
            if not data:
                break
            
            buffer += data
            # پردازش فریم‌های دریافتی بر اساس Line Delimiter (\n)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                
                try:
                    request = json.loads(line)
                except json.JSONDecodeError:
                    send_response(ssl_sock, {
                        "status": "error",
                        "code": "INVALID_REQUEST",
                        "message": "Malformed JSON payload"
                    })
                    continue
                
                action = request.get("action")
                
                # ۱. لاگین
                if action == "login":
                    username = request.get("username", "").strip()
                    password = request.get("password", "")
                    last_msg_id = request.get("last_msg_id", 0)
                    
                    if not username or not password:
                        send_response(ssl_sock, {
                            "status": "error",
                            "code": "INVALID_REQUEST",
                            "message": "Username and password are required"
                        })
                        continue
                    
                    # بررسی ورود مجدد
                    with online_lock:
                        if username in online_clients:
                            send_response(ssl_sock, {
                                "status": "error",
                                "code": "ALREADY_ONLINE",
                                "message": "User is already logged in"
                            })
                            continue
                    
                    # احراز هویت یا ثبت‌نام خودکار برای راحتی فاز تست پروژه
                    if not verify_user(username, password):
                        # اگر کاربر وجود ندارد، اقدام به ثبت نام کن
                        success = register_user(username, password)
                        if not success:
                            send_response(ssl_sock, {
                                "status": "error",
                                "code": "INVALID_CREDENTIALS",
                                "message": "Invalid password or registration failed"
                            })
                            continue
                        logging.info(f"Registered new user: {username}")

                    # ثبت کاربر در دیتابیس آنلاین‌ها
                    with online_lock:
                        online_clients[username] = ssl_sock
                        current_user = username
                    
                    logging.info(f"User '{username}' logged in successfully.")
                    
                    # استخراج پیام‌های از دست رفته
                    missed = get_missed_messages(last_msg_id)
                    
                    send_response(ssl_sock, {
                        "status": "success",
                        "message": "Login successful",
                        "missed_messages": missed
                    })
                    
                    # اطلاع به بقیه
                    system_msg_id, system_time = save_message("System", f"{username} joined the chat room.")
                    broadcast({
                        "type": "broadcast",
                        "id": system_msg_id,
                        "sender": "System",
                        "content": f"{username} joined the chat room.",
                        "time": system_time
                    }, exclude_username=username)
                
                # ۲. ورود مجدد با ریکانکت
                elif action == "reconnect":
                    username = request.get("username", "").strip()
                    password = request.get("password", "")
                    last_msg_id = request.get("last_msg_id", 0)
                    
                    if not verify_user(username, password):
                        send_response(ssl_sock, {
                            "status": "error",
                            "code": "INVALID_CREDENTIALS",
                            "message": "Reconnection failed: authentication error"
                        })
                        continue
                    
                    with online_lock:
                        # بستن سوکت قبلی در صورت وجود
                        if username in online_clients:
                            try:
                                online_clients[username].close()
                            except:
                                pass
                        online_clients[username] = ssl_sock
                        current_user = username
                    
                    logging.info(f"User '{username}' reconnected.")
                    missed = get_missed_messages(last_msg_id)
                    
                    send_response(ssl_sock, {
                        "status": "success",
                        "message": "Reconnected successfully",
                        "missed_messages": missed
                    })
                    
                # ۳. عملیات نیازمند احراز هویت
                elif action in ["send_msg", "get_users", "logout"]:
                    if not current_user:
                        send_response(ssl_sock, {
                            "status": "error",
                            "code": "AUTH_REQUIRED",
                            "message": "Authentication required to perform this action"
                        })
                        continue
                    
                    if action == "send_msg":
                        content = request.get("content", "").strip()
                        if not content:
                            send_response(ssl_sock, {
                                "status": "error",
                                "code": "INVALID_REQUEST",
                                "message": "Message content cannot be empty"
                            })
                            continue
                        
                        # کنترل اسپم
                        if is_rate_limited(current_user):
                            logging.warning(f"Rate limit exceeded for user: {current_user}")
                            send_response(ssl_sock, {
                                "status": "error",
                                "code": "RATE_LIMITED",
                                "message": "Rate limit exceeded. Please wait a moment."
                            })
                            continue
                            
                        # ذخیره و برودکست پیام
                        msg_id, msg_time = save_message(current_user, content)
                        
                        send_response(ssl_sock, {
                            "status": "success",
                            "message": "Message sent",
                            "message_id": msg_id
                        })
                        
                        broadcast({
                            "type": "chat",
                            "id": msg_id,
                            "sender": current_user,
                            "content": content,
                            "time": msg_time
                        })
                        
                    elif action == "get_users":
                        with online_lock:
                            users_list = list(online_clients.keys())
                        
                        send_response(ssl_sock, {
                            "type": "user_list",
                            "users": users_list
                        })
                        
                    elif action == "logout":
                        send_response(ssl_sock, {
                            "status": "success",
                            "message": "Logged out successfully"
                        })
                        break  # حلقه پردازش متوقف شده و سوکت بسته می‌شود
                
                else:
                    send_response(ssl_sock, {
                        "status": "error",
                        "code": "UNKNOWN_ACTION",
                        "message": f"Action '{action}' is not supported"
                    })
                    
    except ConnectionResetError:
        logging.warning(f"Connection reset by client {addr}")
    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")
    finally:
        # مدیریت خروج ناگهانی کاربر
        if current_user:
            with online_lock:
                if online_clients.get(current_user) == ssl_sock:
                    online_clients.pop(current_user, None)
            
            logging.info(f"User '{current_user}' disconnected.")
            
            # برودکست برای اطلاع‌رسانی به بقیه اعضا
            system_msg_id, system_time = save_message("System", f"{current_user} left the chat room.")
            broadcast({
                "type": "broadcast",
                "id": system_msg_id,
                "sender": "System",
                "content": f"{current_user} left the chat room.",
                "time": system_time
            })
            
        try:
            ssl_sock.close()
        except:
            pass

# اجرای سرور
def run_server():
    init_db()
    
    # ساختن ساختار TLS Context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # بارگذاری گواهی و کلید خصوصی
    cert_file = os.path.join(CERT_DIR, 'server.crt')
    key_file = os.path.join(CERT_DIR, 'server.key')
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logging.critical(
            f"TLS Certificates not found in '{CERT_DIR}/'. "
            "Please generate server.crt and server.key before running the server."
        )
        return
        
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    
    # راه‌اندازی TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    
    logging.info(f"Secure Chat Server running on TLS://{HOST}:{PORT}")
    
    try:
        while True:
            client_sock, addr = server_socket.accept()
            try:
                # Wrap کردن سوکت TCP با پروتکل TLS
                ssl_sock = context.wrap_socket(client_sock, server_side=True)
                client_thread = threading.Thread(target=handle_client, args=(ssl_sock, addr), daemon=True)
                client_thread.start()
            except ssl.SSLError as ssl_err:
                logging.error(f"TLS Handshake failed with {addr}: {ssl_err}")
                try:
                    client_sock.close()
                except:
                    pass
    except KeyboardInterrupt:
        logging.info("Server is shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    run_server()
