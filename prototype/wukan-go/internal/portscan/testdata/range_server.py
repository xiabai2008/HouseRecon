"""
端口扫描本地靶场 — 长期运行版

用途：为 wukan ports 提供可控的验证目标。
覆盖：HTTP(banner) / 无banner / MySQL greeting / 立即关闭 / 无响应
"""
import socket, threading, time, sys

# port → (banner, delay_before_send)
SERVICES = {
    18080: (b'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nX-Powered-By: PHP/8.2.0\r\nContent-Length: 2\r\n\r\nhi', 0),
    18081: (b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 2\r\n\r\nok', 0),
    18443: (b'', 0),  # TLS 端口但不响应 banner
    13306: (b'5.7.42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 0),  # MySQL greeting
    14422: (b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\x0d\x0a', 0),
    19999: (b'', 0.5),  # 延迟发送
    19998: (None, 0),   # 立即关闭连接
}

def serve(sock, banner, delay):
    while True:
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=handle, args=(conn, banner, delay), daemon=True).start()

def handle(conn, banner, delay):
    try:
        if banner is None:
            conn.close(); return
        if delay:
            time.sleep(delay)
        if banner:
            conn.sendall(banner)
            conn.settimeout(1.5)
            try:
                data = conn.recv(2048)
                # HTTP 类：收到请求后补响应
                if data.startswith((b'HEAD', b'GET')):
                    conn.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
            except socket.timeout:
                pass
        time.sleep(0.1)
    except OSError:
        pass
    finally:
        try: conn.close()
        except: pass

def main():
    socks = []
    for port, (banner, delay) in SERVICES.items():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('127.0.0.1', port))
            s.listen(50)
            s.settimeout(0.5)
            socks.append((s, banner, delay))
            print(f'  [OPEN ] 127.0.0.1:{port}', flush=True)
        except OSError as e:
            print(f'  [SKIP ] 127.0.0.1:{port}  {e}', flush=True)
            s.close()

    print(f'READY {len(socks)} ports', flush=True)
    # 无限运行
    while True:
        for s, b, d in socks:
            threading.Thread(target=serve, args=(s, b, d), daemon=True).start()
        time.sleep(1)

if __name__ == '__main__':
    main()
