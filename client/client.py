import socket
import ssl
import threading
import json
import time

# ==========================================
# تنظیمات اولیه اتصال به سرور چت امن
# ==========================================
SERVER_HOST = '26.222.179.8'  # آدرس آی‌پای سرور
SERVER_PORT = 8443            # پورت اختصاص داده شده به سرویس چت SSL/TLS

class ChatClient:
    """
    کلاس مدیریت کلاینت چت روم امن
    پشتیبانی کامل از TCP Framing با Buffer، احراز هویت، Reconnect و دریافت آنلاین پیام‌ها.
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ssl_sock = None
        self.username = None
        self.password = None
        self.running = False
        self.last_message_id = 0  # ذخیره آخرین شناسه پیام دریافتی جهت سناریوی Reconnect
        self.buffer = ""          # بافر اختصاصی جهت پردازش صحیح TCP Framing (\n)

    def create_ssl_context(self):
        """
        ایجاد کانتکست امنیتی TLS برای رمزنگاری کانال ارتباطی
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
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
            self.buffer = ""  # ریست کردن بافر در هر اتصال جدید
            return True
        except Exception as e:
            print(f"\n[!] خطا در برقراری ارتباط امن با سرور: {e}")
            return False

    def send_json(self, data):
        """
        ارسال داده‌ها با فرمت JSON به همراه کاراکتر Delimiter (\n) جهت TCP Framing
        """
        try:
            json_data = json.dumps(data)
            self.ssl_sock.sendall((json_data + "\n").encode("utf-8"))
        except Exception as e:
            print(f"\n[!] خطا در ارسال بسته داده: {e}")

    def read_line(self):
        """
        خواندن یک خط کامل از سوکت بر اساس '\n' (حل کامل مشکل TCP Framing)
        """
        while "\n" not in self.buffer:
            try:
                data = self.ssl_sock.recv(4096).decode('utf-8')
                if not data:
                    return None
                self.buffer += data
            except Exception:
                return None

        line, self.buffer = self.buffer.split("\n", 1)
        return line.strip()

    def receive_json(self):
        """
        دریافت و پارس کردن یک شیء JSON از بافر
        """
        line = self.read_line()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def authenticate(self):
        """
        فرآیند دریافت اطلاعات کاربری و ارسال بسته احراز هویت به سرور
        """
        print("\n=== ورود به سیستم چت امن ===")
        self.username = input("نام کاربری: ").strip()
        self.password = input("رمز عبور: ").strip()

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
            
            # دریافت و نمایش پیام‌های از دست رفته در زمان غیبت
            if "missed_messages" in response and response["missed_messages"]:
                print("\n--- 📩 پیام‌های دریافتی در زمان غیبت شما ---")
                for msg in response["missed_messages"]:
                    print(f"[{msg['time']}] {msg['sender']}: {msg['content']}")
                    self.last_message_id = max(self.last_message_id, msg.get('id', 0))
                print("-------------------------------------------\n")
            return True
        else:
            reason = response.get("message", "عدم پاسخگویی سرور") if response else "عدم پاسخگویی سرور"
            print(f"[-] ورود ناموفق: {reason}")
            return False

    def receive_messages(self):
        """
        ترد (Thread) مجزا برای دریافت ناهمگام پیام‌ها از سرور به صورت آنلاین
        """
        while self.running:
            data = self.receive_json()
            if data:
                msg_type = data.get("type")
                status = data.get("status")
                
                # مدیریت هشدارها (مثل Rate Limit یا خطاهای سرور)
                if status == "error":
                    print(f"\n[!] خطا از طرف سرور: {data.get('message')}\n> ", end="")

                # دریافت پیام‌های چت یا برودکست سیستم
                elif msg_type in ["chat", "broadcast"]:
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
                # مدیریت قطعی اتصال
                if self.running:
                    print("\n[!] اتصال به سرور قطع شد! در حال تلاش برای بازیابی ارتباط...")
                    self.reconnect()
                break

    def reconnect(self):
        """
        الگوریتم تلاش مجدد (Reconnection Mechanism) و دریافت پیام‌های Missed
        """
        try:
            self.ssl_sock.close()
        except:
            pass

        while self.running:
            time.sleep(3)
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
                    
                    # دریافت پیام‌های زمان قطعی
                    if "missed_messages" in res and res["missed_messages"]:
                        print("\n--- 📩 پیام‌های زمان قطعی ---")
                        for msg in res["missed_messages"]:
                            print(f"[{msg['time']}] {msg['sender']}: {msg['content']}")
                            self.last_message_id = max(self.last_message_id, msg.get('id', 0))
                        print("----------------------------\n")

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
        
        recv_thread = threading.Thread(target=self.receive_messages, daemon=True)
        recv_thread.start()

        print("\n--- چت‌روم فعال گردید ---")
        print("دستورات: '/users' (مشاهده آنلاین‌ها) | '/exit' (خروج از برنامه)\n")

        while self.running:
            try:
                msg = input("> ").strip()
                if not msg:
                    continue

                if msg.lower() == '/exit':
                    self.running = False
                    self.send_json({"action": "logout"})
                    print("در حال خروج از چت‌روم...")
                    break
                elif msg.lower() == '/users':
                    self.send_json({"action": "get_users"})
                else:
                    self.send_json({
                        "action": "send_msg",
                        "content": msg
                    })
            except (KeyboardInterrupt, EOFError):
                self.running = False
                break

        if self.ssl_sock:
            try:
                self.ssl_sock.close()
            except:
                pass

if __name__ == '__main__':
    client = ChatClient(SERVER_HOST, SERVER_PORT)
    client.start()