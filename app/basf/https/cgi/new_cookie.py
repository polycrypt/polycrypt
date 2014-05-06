#!/usr/bin/env python

import Cookie
import time


rcvd = {}
try:
    rcvd = Cookie.SimpleCookie(os.environ['HTTP_COOKIE'])
except:
    pass

string = ''
for k,v in rcvd:
    string += k + '=' + v + '; '

received = Cookie.SimpleCookie()
received['text'] = string

cookie = Cookie.SimpleCookie()
cookie['heartbeat'] = int(time.time())
cookie['heartbeat']['path'] = '/' 
cookie['heartbeat']['Expires'] = 3600

print received
print cookie

'''
logic from server's side

init
    x



logic from client's side
init
    x
    012345678901234


'''

