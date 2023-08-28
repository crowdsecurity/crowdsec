#!/usr/bin/env python3

import datetime
import json
import logging
import sys
import urllib

from http.server import HTTPServer, BaseHTTPRequestHandler


class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        logging.info("Request path: %s", self.path)

        parsed_path = urllib.parse.urlparse(self.path)
        routes = {
            '/': self.root,
            '/v3/watchers/login': self.v3_watchers_login,
        }

        if parsed_path.path in routes:
            routes[parsed_path.path]()
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'404 Not found')

    def log_message(self, format, *args):
        return

    def root(self):
        request_body = self.rfile.read(int(self.headers['Content-Length']))
        request_body = json.loads(request_body.decode())
        log = {
            "path": self.path,
            "status": 200,
            "request_body": request_body,
        }
        print(json.dumps(log))
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({}).encode())
        self.wfile.flush()

    def v3_watchers_login(self):
        j = {
            'code': 200,
            'token': '',
            'expire': datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(j).encode())
        self.wfile.flush()


def main(argv):
    try:
        port = int(argv[1])
    except IndexError:
        logging.fatal("Missing port number")
        return 1
    except ValueError:
        logging.fatal("Invalid port number '%s'", argv[1])
        return 1
    server = HTTPServer(('', port), RequestHandler)
    # logging.info('Listening on port %s', port)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main(sys.argv))
