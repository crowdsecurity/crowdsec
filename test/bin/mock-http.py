#!/usr/bin/env python3

import json
import logging
import sys

from http.server import HTTPServer, BaseHTTPRequestHandler


class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        request_path = self.path
        content_length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(content_length).decode() if content_length > 0 else ""
        request_body = json.loads(raw_body) if raw_body else None
        log = {
            "path": request_path,
            "status": 200,
            "request_body": request_body,
        }
        print(json.dumps(log))
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({}).encode())
        self.wfile.flush()
        return

    def log_message(self, format, *args):
        return


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
