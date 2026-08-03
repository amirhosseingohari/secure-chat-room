import socket
import ssl
import threading
import json
import time

# ==========================================
# تنظیمات اولیه اتصال به سرور چت امن
# ==========================================
SERVER_HOST = '0.0.0.0'  # آدرس آی‌پای سرور (در صورت اجرا روی سیستم مجزا تغییر یابد)
SERVER_PORT = 8443        # پورت اختصاص داده شده به سرویس چت SSL/TLS

class ChatClient:
    """
    کلاس مدیریت کلاینت چت روم امن
    این کلاس مسئول برقراری ارتباط SSL/TLS، احراز هویت، ارسال/دریافت پیام و
    تلاش برای اتصال مجدد (Reconnect) در صورت قطعی شبکه می‌باشد.
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ssl_sock = None
        self.username = None
        self.password = None
        self.running = False
        self.last_message_id = 0  # ذخیره آخرین شناسه پیام دریافتی جهت سناریوی Reconnect

    def create_ssl_context(self):
        """
        ایجاد کانتکست امنیتی TLS برای رمزنگاری کانال ارتباطی
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # غیرفعال‌سازی بررسی نام هاست و گواهی‌نامه به دلیل استفاده از Self-Signed Certificate در فاز توسعه
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def connect(self):
        """
        ایجاد سوکت TCP و ارتقاء آن به یک سوکت امن SSL/TLS
        """
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = self.create_ssl_context()
            self.ssl_sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            self.ssl_sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"\n[!] خطا در برقراری ارتباط امن با سرور: {e}")
            return False

    def authenticate(self):
        """
        فرآیند دریافت اطلاعات کاربری و ارسال بسته احراز هویت به سرور
        """
        print("\n=== ورود به سیستم چت امن ===")
        self.username = input("نام کاربری: ").strip()
        self.password = input("رمز عبور: ").strip()

        # بسته درخواست ورود با فرمت JSON
        auth_payload = {
            "action": "login",
            "username": self.username,
            "password": self.password,
            "last_msg_id": self.last_message_id
        }
        
        self.send_json(auth_payload)
        response = self.receive_json()

        if response and response.get("status") == "success":
            print(f"\n[+] احراز هویت موفقیت‌آمیز بود! خوش آمدید {self.username}.")
            
            # دریافت و نمایش پیام‌های از دست رفته در زمان قطعی یا ورود مجدد
            if "missed_messages" in response and response["missed_messages"]:
                print("\n--- 📩 پیام‌های دریافتی در زمان غیبت شما ---")
                for msg in response["missed_messages"]:
                    print(f"[{msg['time']}] {msg['sender']}: {msg['content']}")
                    self.last_message_id = max(self.last_message_id, msg.get('id', 0))
                print("-------------------------------------------\n")
            return True
        else:
            reason = response.get("message", "پاسخی دریافت نشد") if response else "عدم پاسخگویی سرور"
            print(f"[-] ورود ناموفق: {reason}")
            return False

    def send_json(self, data):
        """
        توابع کمکی جهت تبدیل داده‌ها به JSON و ارسال روی سوکت TLS
        """
        try:
            json_data = json.dumps(data)
            self.ssl_sock.sendall((json_data + "\n").encode("utf-8"))
        except Exception as e:
            print(f"\n[!] خطا در ارسال بسته داده: {e}")

    def receive_json(self):
        """
        توابع کمکی جهت خواندن داده از سوکت و تبدیل آن به شیء JSON
        """
        try:
            data = self.ssl_sock.recv(4096).decode('utf-8')
            if not data:
                return None
            return json.loads(data)
        except Exception:
            return None

    def receive_messages(self):
        """
        ترد (Thread) مجزا برای دریافت ناهمگام پیام‌ها از سرور به صورت آنلاین
        """
        while self.running:
            data = self.receive_json()
            if data:
                msg_type = data.get("type")
                
                # دریافت پیام‌های عمومی یا برودکست سیستم
                if msg_type in ["chat", "broadcast"]:
                    sender = data.get("sender", "System")
                    content = data.get("content", "")
                    timestamp = data.get("time", "")
                    msg_id = data.get("id", 0)
                    
                    if msg_id:
                        self.last_message_id = max(self.last_message_id, msg_id)

                    print(f"\n[{timestamp}] {sender}: {content}\n> ", end="")
                
                # دریافت لیست کاربران آنلاین
                elif msg_type == "user_list":
                    users = data.get("users", [])
                    print(f"\n[لیست کاربران آنلاین ({len(users)} نفر)]: {', '.join(users)}\n> ", end="")
            else:
                # مدیریت قطعی اتصال سرور
                if self.running:
                    print("\n[!] اتصال به سرور قطع شد! تلاش برای بازیابی ارتباط...")
                    self.reconnect()
                break

    def reconnect(self):
        """
        الگوریتم تلاش مجدد (Reconnection Mechanism) و دریافت پیام‌های Missed
        """
        self.ssl_sock.close()
        while self.running:
            time.sleep(3)  # وقفه ۳ ثانیه‌ای بین هر تلاش
            print("[...] در حال تلاش برای اتصال مجدد به سرور...")
            if self.connect():
                reconnect_payload = {
                    "action": "reconnect",
                    "username": self.username,
                    "password": self.password,
                    "last_msg_id": self.last_message_id
                }
                self.send_json(reconnect_payload)
                res = self.receive_json()
                if res and res.get("status") == "success":
                    print("[+] ارتباط مجدد با موفقیت برقرار گردید!")
                    # راه‌اندازی مجدد ترد دریافت پیام
                    threading.Thread(target=self.receive_messages, daemon=True).start()
                    break

    def start(self):
        """
        نقطه ورود اصلی اجرای کلاینت و مدیریت حلقه CLI
        """
        if not self.connect():
            return

        if not self.authenticate():
            self.ssl_sock.close()
            return

        self.running = True
        
        # اجرای ترد پس‌زمینه برای دریافت آنلاین پیام‌ها
        recv_thread = threading.Thread(target=self.receive_messages, daemon=True)
        recv_thread.start()

        print("\n--- چت‌روم فعال گردید ---")
        print("دستورات: '/users' (مشاهده آنلاین‌ها) | '/exit' (خروج از برنامه)\n")

        # حلقه گرفتن ورودی از کاربر در خط فرمان (CLI)
        while self.running:
            try:
                msg = input("> ").strip()
                if not msg:
                    continue

                if msg.lower() == '/exit':
                    self.running = False
                    self.send_json({"action": "logout", "username": self.username})
                    print("در حال خروج از چت‌روم...")
                    break
                elif msg.lower() == '/users':
                    self.send_json({"action": "get_users"})
                else:
                    self.send_json({
                        "action": "send_msg",
                        "content": msg,
                        "username": self.username
                    })
            except (KeyboardInterrupt, EOFError):
                self.running = False
                break

        if self.ssl_sock:
            self.ssl_sock.close()

if __name__ == '__main__':
    client = ChatClient(SERVER_HOST, SERVER_PORT)
    client.start()
