#!/usr/bin/env python3
import queue
import threading
import os
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import sys
import time

# === CONFIG ===
threads = 10
target = "http://127.0.0.1:8000"   # <- обязательно с http(s):// и без trailing slash
directory = "joomla"               # локальная папка со списком файлов для пробования
filters = {".jpg", ".jpeg", ".gif", ".png", ".css"}  # расширения, которые НЕ тестируем
timeout = 5  # seconds per request
# ==============

# sanity
if not target.startswith("http://") and not target.startswith("https://"):
    print("Error: target must start with http:// or https://")
    sys.exit(1)

if not os.path.isdir(directory):
    print(f"Error: directory '{directory}' not found")
    sys.exit(1)

# make sure there is no trailing slash in target
target = target.rstrip("/")

web_paths = queue.Queue()

# collect paths
for root, dirs, files in os.walk(directory):
    for fname in files:
        ext = os.path.splitext(fname)[1].lower()
        if ext in filters:
            continue
        rel_dir = os.path.relpath(root, directory)
        if rel_dir == ".":
            remote_path = f"/{fname}"
        else:
            remote_path = f"/{rel_dir.replace(os.sep, '/')}/{fname}"
        web_paths.put(remote_path)

if web_paths.empty():
    print("[*] No paths to test (queue empty). Exiting.")
    sys.exit(0)

print(f"[*] Loaded {web_paths.qsize()} paths to test. Starting {threads} threads.")

print_lock = threading.Lock()

def test_remote():
    # basic headers to look like a browser
    headers = {"User-Agent": "Mozilla/5.0 (dir-probe) Python script"}
    while True:
        try:
            path = web_paths.get_nowait()
        except queue.Empty:
            break

        url = target + path
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                # read small amount to avoid huge downloads (optional)
                # body = resp.read(1024)
                with print_lock:
                    print(f"{code} => {url}")
        except HTTPError as e:
            # Print only interesting codes (403/401/500 etc.) or skip 404/no-permission noise
            if e.code not in (404,):
                with print_lock:
                    print(f"{e.code} => {url}")
        except URLError as e:
            # connection refused / timeout / name error
            with print_lock:
                print(f"ERR  => {url} ({e.reason})")
        except Exception as e:
            with print_lock:
                print(f"EXC  => {url} ({e})")
        finally:
            web_paths.task_done()
        # polite pause to avoid hammering a server
        time.sleep(0.01)


workers = []
for i in range(threads):
    t = threading.Thread(target=test_remote, name=f"worker-{i}", daemon=True)
    t.start()
    workers.append(t)

# wait until queue is processed
web_paths.join()

print("[*] Done.")
