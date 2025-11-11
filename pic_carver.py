#!/usr/bin/env python3
import os
import zlib
import cv2
from scapy.all import rdpcap, TCP

# Настройки
pictures_directory = "extracted_pics"
faces_directory = "faces"
pcap_file = "bhp.pcap"   # поставь сюда свой pcap

# Haarcascade (скачай из OpenCV или установи путь корректный)
CASCADE_FILE = "haarcascade_frontalface_alt.xml"


def ensure_dirs():
    os.makedirs(pictures_directory, exist_ok=True)
    os.makedirs(faces_directory, exist_ok=True)


def face_detect(image_path, out_name):
    """Возвращает True если лицо найдено, сохраняет изображение с прямоугольниками."""
    img = cv2.imread(image_path)
    if img is None:
        return False
    cascade = cv2.CascadeClassifier(CASCADE_FILE)
    if cascade.empty():
        raise RuntimeError(f"Failed to load cascade file: {CASCADE_FILE}")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    rects = cascade.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=4, minSize=(20, 20))
    if len(rects) == 0:
        return False
    for (x, y, w, h) in rects:
        cv2.rectangle(img, (x, y), (x + w, y + h), (127, 255, 0), 2)
    out_path = os.path.join(faces_directory, out_name)
    cv2.imwrite(out_path, img)
    return True


def get_http_headers(http_payload_bytes):
    """Возвращает dict заголовков (keys в нижнем регистре) или None."""
    try:
        idx = http_payload_bytes.index(b"\r\n\r\n") + 4
    except ValueError:
        return None
    headers_raw = http_payload_bytes[:idx].decode("iso-8859-1", errors="ignore")
    # извлекаем строк заголовков (до пустой строки)
    lines = headers_raw.split("\r\n")
    # первая строка — статус/запрос, пропускаем
    header_lines = lines[1:]
    headers = {}
    for line in header_lines:
        if not line.strip():
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            name = parts[0].strip().lower()
            value = parts[1].strip()
            headers[name] = value
    # убедимся, что есть content-type
    if "content-type" not in headers:
        return None
    return headers


def extract_image(headers, http_payload_bytes):
    """Если в заголовках есть image/* — вернёт (bytes, ext) или (None, None)."""
    try:
        ctype = headers.get("content-type", "")
        if "image" not in ctype:
            return None, None
        image_type = ctype.split("/")[1].split(";")[0].strip()  # 'jpeg', 'png', ...
        # отделим тело от заголовков
        body_idx = http_payload_bytes.index(b"\r\n\r\n") + 4
        image = http_payload_bytes[body_idx:]
        # декодирование при content-encoding
        cencoding = headers.get("content-encoding", "").lower()
        if cencoding:
            if "gzip" in cencoding:
                # gzip wrapper
                image = zlib.decompress(image, 16 + zlib.MAX_WBITS)
            elif "deflate" in cencoding:
                image = zlib.decompress(image)
        return image, image_type
    except Exception:
        return None, None


def http_assembler(pcap_file):
    ensure_dirs()
    carved_images = 0
    faces_detected = 0

    packets = rdpcap(pcap_file)
    sessions = packets.sessions()

    for session_key, pkts in sessions.items():
        http_payload = b""
        for packet in pkts:
            if packet.haslayer(TCP):
                try:
                    # port 80 check
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    if sport == 80 or dport == 80:
                        payload = bytes(packet[TCP].payload)
                        if payload:
                            http_payload += payload
                except Exception:
                    pass
        if not http_payload:
            continue
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        image, image_type = extract_image(headers, http_payload)
        if image is not None and image_type is not None:
            file_name = f"{os.path.splitext(os.path.basename(pcap_file))[0]}_pic_{carved_images}.{image_type}"
            out_path = os.path.join(pictures_directory, file_name)
            with open(out_path, "wb") as f:
                f.write(image)
            carved_images += 1
            try:
                result = face_detect(out_path, file_name)
                if result:
                    faces_detected += 1
            except Exception:
                pass

    return carved_images, faces_detected


if __name__ == "__main__":
    carved_images, faces_detected = http_assembler(pcap_file)
    print(f"Extracted: {carved_images} images")
    print(f"Detected: {faces_detected} faces")
