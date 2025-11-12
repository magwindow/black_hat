# test_server.py - простой тестовый сервер
from http.server import HTTPServer, BaseHTTPRequestHandler

class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''
        <form method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
        '''
        self.wfile.write(html.encode())
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.wfile.read(content_length).decode()
        
        if 'username=admin&password=test' in post_data:
            self.send_response(200)
            self.wfile.write(b'Success! Dashboard')
        else:
            self.send_response(200)
            self.wfile.write(b'Login Failed')

print("Starting test server on http://localhost:8080")
HTTPServer(('localhost', 8080), TestHandler).serve_forever()