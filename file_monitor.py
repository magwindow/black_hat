#!/usr/bin/env python3
import os
import time
import threading
import win32file
import win32con
import traceback
from queue import Queue

# директории для мониторинга (проверь их на твоей системе)
dirs_to_monitor = [
    r"C:\WINDOWS\Temp",
    os.getenv("TEMP") or os.getenv("TMP") or os.path.expanduser("~\\AppData\\Local\\Temp")
]

# сопоставление кодов действий от ReadDirectoryChangesW
ACTION_MAP = {
    1: "Created",
    2: "Deleted",
    3: "Modified",
    4: "Renamed From",
    5: "Renamed To",
}

# максимальный байт-дамп для печати (чтобы не залить консоль)
MAX_DUMP = 4096

# для контроля завершения потоков
stop_event = threading.Event()


def safe_hexdump(data: bytes, max_bytes: int = 256) -> str:
    # компактный hex+ascii дамп (первые max_bytes байт)
    if not data:
        return "<empty>"
    display = data[:max_bytes]
    hexpart = " ".join(f"{b:02X}" for b in display)
    asciipart = "".join((chr(b) if 32 <= b < 127 else ".") for b in display)
    if len(data) > max_bytes:
        return f"{hexpart} ...\nASCII: {asciipart} ..."
    return f"{hexpart}\nASCII: {asciipart}"


def start_monitor(path_to_watch):
    FILE_LIST_DIRECTORY = win32con.FILE_LIST_DIRECTORY if hasattr(win32con, "FILE_LIST_DIRECTORY") else 0x0001
    try:
        # Получаем handle директории
        h_directory = win32file.CreateFile(
            path_to_watch,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    except Exception as e:
        print(f"[!] Failed to open directory {path_to_watch}: {e}")
        return

    print(f"[*] Started monitoring: {path_to_watch}")

    while not stop_event.is_set():
        try:
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                8192,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME
                | win32con.FILE_NOTIFY_CHANGE_DIR_NAME
                | win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES
                | win32con.FILE_NOTIFY_CHANGE_SIZE
                | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE
                | win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None,
            )
            for action, file_name in results:
                try:
                    # file_name обычно str
                    full_path = os.path.join(path_to_watch, file_name)
                except Exception:
                    full_path = os.path.join(path_to_watch, str(file_name))

                action_name = ACTION_MAP.get(action, f"Unknown({action})")
                print(f"[{action_name}] {full_path}")

                # при модификации попытаемся прочитать кусок файла
                if action == 3:  # Modified
                    print("    [*] Attempting to dump contents (first bytes)...")
                    try:
                        # может быть файл занят — пробуем несколько раз с таймаутом
                        for attempt in range(3):
                            try:
                                with open(full_path, "rb") as fd:
                                    data = fd.read(MAX_DUMP)
                                print("    [vvv] Dump start")
                                print(safe_hexdump(data, max_bytes=256))
                                print("    [^^^] Dump end")
                                break
                            except (PermissionError, IOError):
                                time.sleep(0.2)
                        else:
                            print("    [!!!] Could not read file (locked or deleted).")
                    except Exception as e:
                        print("    [!!!] Exception while reading file:", e)
                        traceback.print_exc()
        except Exception as e:
            # ReadDirectoryChangesW может падать при удалении директории или других проблемах
            print(f"[!] ReadDirectoryChangesW error for {path_to_watch}: {e}")
            # короткая пауза, чтобы не печатать миллионы ошибок подряд
            time.sleep(1)

    try:
        win32file.CloseHandle(h_directory)
    except Exception:
        pass
    print(f"[*] Stopped monitoring: {path_to_watch}")


def main():
    threads = []
    # проверяем и запускаем мониторинг только для существующих путей
    for path in dirs_to_monitor:
        if not path:
            continue
        if not os.path.isdir(path):
            print(f"[!] Skipping (not a directory): {path}")
            continue
        t = threading.Thread(target=start_monitor, args=(path,), daemon=True)
        t.start()
        threads.append(t)
        print(f"Spawned monitor thread for: {path}")

    print("[*] Monitoring. Press Ctrl-C to exit.")
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Ctrl-C received, stopping monitors...")
        stop_event.set()
        # даём потокам время завершиться
        for t in threads:
            t.join(timeout=2)
    print("[*] All done.")


if __name__ == "__main__":
    main()
