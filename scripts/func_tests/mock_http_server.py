import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        request_path = self.path
        request_body = self.rfile.read(int(self.headers['Content-Length']))
        request_body = json.loads(request_body.decode())
        log = {
            "path": request_path,
            "status": 200, 
            "request_body": request_body,
        }
        print(json.dumps(log))
        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps({}).encode())
        return
    
    def log_message(self, format, *args):
        return

if __name__ == "__main__" :
    server = HTTPServer(('', 9999), RequestHandler)
    server.serve_forever()