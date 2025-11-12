#!/usr/bin/env python3
import os
import sys
import time
import queue
import threading
from urllib.parse import quote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# === CONFIG ===
threads = 20
target_url = "http://testphp.vulnweb.com"   # <-- укажи тестовый target (http://testphp.vulnweb.com можно использовать)
wordlist_file = "all.txt"                   # wordlist (по одной записи на строку)
resume = None                               # если хочешь восстановить с какого-то слова, впиши его (строка)
user_agent = "Mozilla/5.0 (dir-brute) Python"
timeout = 6                                 # seconds
throttle = 0.01                             # pause between requests (politeness)
extensions = [".php", ".bak", ".orig", ".inc"]
# ==============

if not target_url.startswith("http://") and not target_url.startswith("https://"):
    print("target_url must start with http:// or https://")
    sys.exit(1)

if not os.path.isfile(wordlist_file):
    print(f"Wordlist file '{wordlist_file}' not found.")
    sys.exit(1)


def build_wordlist(path, resume_word=None):
    q = queue.Queue()
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
    return q


def worker(q: queue.Queue):
    headers = {"User-Agent": user_agent}
    while True:
        try:
            word = q.get_nowait()
        except queue.Empty:
            break

        candidates = []
        if "." not in word:
            candidates.append(f"/{word}/")
        candidates.append(f"/{word}")
        for ext in extensions:
            candidates.append(f"/{word}{ext}")

        for candidate in candidates:
            # quote only path portion
            safe_path = quote(candidate)
            url = target_url.rstrip("/") + safe_path
            req = Request(url, headers=headers)
            try:
                with urlopen(req, timeout=timeout) as resp:
                    code = resp.getcode()
                    # read small chunk to ensure real content and avoid big downloads
                    # (we don't need full body)
                    _ = resp.read(64)
                    print(f"[{code}] {url}")
            except HTTPError as he:
                # show interesting codes (403/401/500 etc.), ignore 404 by default
                if he.code != 404:
                    print(f"[{he.code}] {url} ({he.reason})")
            except URLError as ue:
                print(f"[ERR] {url} ({ue.reason})")
            except Exception as e:
                print(f"[EXC] {url} ({e})")
            time.sleep(throttle)
        q.task_done()


def main():
    q = build_wordlist(wordlist_file, resume)
    print(f"[*] Loaded {q.qsize()} words. Starting {threads} threads.")
    workers = []
    for i in range(threads):
        t = threading.Thread(target=worker, args=(q,), name=f"worker-{i}", daemon=True)
        t.start()
        workers.append(t)

    # wait until queue finished
    q.join()
    print("[*] Done.")

if __name__ == "__main__":
    main()
