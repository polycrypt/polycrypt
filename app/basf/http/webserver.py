#!/usr/bin/env python

import BaseHTTPServer
import CGIHTTPServer
import cgitb

cgitb.enable()

PORT = 8002

server = BaseHTTPServer.HTTPServer
handler = CGIHTTPServer.CGIHTTPRequestHandler
server_address = ("", PORT)
handler.cgi_directories = ['/cgi']

httpd = server(server_address, handler)
print 'starting server on localhost:{0}'.format(str(PORT))
httpd.serve_forever()

