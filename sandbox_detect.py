import time
import random
import ctypes
import threading

# Загрузка Windows DLL
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# Глобальные счетчики
keystrokes = 0
mouse_clicks = 0
double_clicks = 0

class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_ulong)]

def get_last_input():
    """Получение времени последнего ввода пользователя"""
    struct_lastinputinfo = LASTINPUTINFO()
    struct_lastinputinfo.cbSize = ctypes.sizeof(LASTINPUTINFO)
    
    # Получаем информацию о последнем вводе
    if user32.GetLastInputInfo(ctypes.byref(struct_lastinputinfo)):
        # Получаем время работы системы
        run_time = kernel32.GetTickCount()
        elapsed = run_time - struct_lastinputinfo.dwTime
        print(f"[*] Прошло {elapsed} миллисекунд с последнего события ввода.")
        return elapsed
    else:
        print("[!] Ошибка получения информации о последнем вводе")
        return 0

def get_key_press():
    """Обнаружение нажатий клавиш и кликов мыши"""
    global mouse_clicks, keystrokes
    
    # Проверяем все возможные коды клавиш
    for i in range(1, 256):  # Начинаем с 1, так как 0 может быть специальным
        if user32.GetAsyncKeyState(i) & 0x8000:  # Проверяем бит "было нажато"
            # 0x1 - код левой кнопки мыши
            if i == 0x1:
                mouse_clicks += 1
                print(f"[+] Клик мыши обнаружен. Всего кликов: {mouse_clicks}")
                return time.time()
            # Коды символов (буквы, цифры, символы)
            elif 32 < i < 127:
                keystrokes += 1
                print(f"[+] Нажатие клавиши: {chr(i)}. Всего нажатий: {keystrokes}")
                return time.time()
            # Специальные клавиши
            elif i in [0x08, 0x09, 0x0D, 0x10, 0x11, 0x12, 0x20]:  # Backspace, Tab, Enter, Shift, Ctrl, Alt, Space
                keystrokes += 1
                key_name = {
                    0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter", 
                    0x10: "Shift", 0x11: "Ctrl", 0x12: "Alt", 0x20: "Space"
                }.get(i, f"Key_{i}")
                print(f"[+] Нажатие клавиши: {key_name}. Всего нажатий: {keystrokes}")
                return time.time()
    
    return None

def monitor_input():
    """Мониторинг ввода в реальном времени"""
    print("[*] Запуск мониторинга ввода...")
    print("[*] Нажимайте клавиши и кликайте мышью для тестирования")
    
    try:
        while True:
            get_key_press()
            time.sleep(0.01)  # Небольшая задержка для снижения нагрузки на CPU
    except KeyboardInterrupt:
        print("\n[*] Мониторинг остановлен пользователем")

def detect_sandbox():
    """Обнаружение песочницы по отсутствию пользовательского ввода"""
    global mouse_clicks, keystrokes
    
    # Случайные пороговые значения
    max_keystrokes = random.randint(5, 15)
    max_mouse_clicks = random.randint(3, 10)
    max_double_clicks = random.randint(2, 5)
    double_click_threshold = 0.35  # секунды
    max_input_threshold = 15000  # миллисекунд (15 секунд)
    
    double_clicks_count = 0
    first_double_click = None
    previous_timestamp = None
    detection_complete = False
    
    print("[*] Запуск детектора песочницы...")
    print(f"[*] Пороги: {max_keystrokes} нажатий, {max_mouse_clicks} кликов, {max_double_clicks} двойных кликов")
    
    # Проверяем время с последнего ввода
    last_input = get_last_input()
    if last_input >= max_input_threshold:
        print(f"[!] Обнаружена песочница! Последний ввод был {last_input} мс назад")
        return False
    else:
        print(f"[+] Время с последнего ввода в норме: {last_input} мс")
    
    start_time = time.time()
    timeout = 30  # Максимальное время ожидания (30 секунд)
    
    print("[*] Ожидание пользовательского ввода...")
    
    while not detection_complete and (time.time() - start_time) < timeout:
        keypress_time = get_key_press()
        
        if keypress_time is not None and previous_timestamp is not None:
            # Вычисляем время между кликами
            elapsed = keypress_time - previous_timestamp
            
            # Проверяем двойной клик
            if elapsed <= double_click_threshold:
                double_clicks_count += 1
                print(f"[+] Двойной клик #{double_clicks_count} обнаружен (интервал: {elapsed:.3f} сек)")
                
                if first_double_click is None:
                    first_double_click = time.time()
                else:
                    if double_clicks_count >= max_double_clicks:
                        total_double_click_time = time.time() - first_double_click
                        expected_time = max_double_clicks * double_click_threshold
                        
                        if total_double_click_time <= expected_time:
                            print(f"[+] Достаточно двойных кликов за короткое время")
                            detection_complete = True
            
            # Проверяем общие пороги
            if (keystrokes >= max_keystrokes and 
                mouse_clicks >= max_mouse_clicks and 
                double_clicks_count >= max_double_clicks):
                detection_complete = True
                print("[+] Обнаружено достаточно пользовательского ввода")
            
            previous_timestamp = keypress_time
            
        elif keypress_time is not None:
            previous_timestamp = keypress_time
        
        # Небольшая пауза для снижения нагрузки
        time.sleep(0.1)
    
    # Проверяем результаты
    if detection_complete:
        print("[+] Система прошла проверку - это не песочница")
        print(f"    Нажатий клавиш: {keystrokes}/{max_keystrokes}")
        print(f"    Кликов мыши: {mouse_clicks}/{max_mouse_clicks}")
        print(f"    Двойных кликов: {double_clicks_count}/{max_double_clicks}")
        return True
    else:
        print("[!] Песочница обнаружена - недостаточно пользовательского ввода")
        print(f"    Нажатий клавиш: {keystrokes}/{max_keystrokes}")
        print(f"    Кликов мыши: {mouse_clicks}/{max_mouse_clicks}")
        print(f"    Двойных кликов: {double_clicks_count}/{max_double_clicks}")
        return False

def main():
    """Основная функция"""
    print("=" * 50)
    print("Детектор песочницы для Windows 11")
    print("=" * 50)
    print("[!] Используйте только для легального тестирования!")
    
    # Запускаем мониторинг в отдельном потоке
    monitor_thread = threading.Thread(target=monitor_input, daemon=True)
    monitor_thread.start()
    
    # Запускаем детектор
    try:
        if detect_sandbox():
            print("\n[+] Результат: Система НЕ является песочницей")
        else:
            print("\n[+] Результат: Возможная песочница обнаружена")
            
        print(f"\nИтоговые счетчики:")
        print(f"  Нажатия клавиш: {keystrokes}")
        print(f"  Клики мыши: {mouse_clicks}")
        
    except KeyboardInterrupt:
        print("\n[*] Программа остановлена пользователем")
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")

if __name__ == "__main__":
    main()