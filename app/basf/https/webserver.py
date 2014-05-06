#!/usr/bin/env python

import BaseHTTPServer
import CGIHTTPServer
import cgitb
import ssl

cgitb.enable()

PORT = 4343

server = BaseHTTPServer.HTTPServer
handler = CGIHTTPServer.CGIHTTPRequestHandler
server_address = ('', PORT)
handler.cgi_directories = ['/cgi']

httpd = server(server_address, handler)

'''
# uncomment this to add ssl
# also s/http/https/ in the links
# note that polycrypt must be in a separate origin, so you'll need to ssl
#     between here and there, too
handler.have_fork = False
httpd.socket = ssl.wrap_socket(httpd.socket,
        keyfile='ssl/key.pem',
        certfile='ssl/cert.pem',
        server_side=True)
'''

print 'starting server on localhost:{0}'.format(str(PORT))
try:
    httpd.serve_forever()
except ssl.SSLError as sslerr:
    print '===== got sslerror ====='
    print sslerr
except Exception as ex:
    print '===== got other error ====='
    print ex

# -----------------------------------------------------------------------------
'''
'''

