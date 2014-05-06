#!/usr/bin/env python

# The beginnings of a file for http cookies.

import Cookie
import json
import os
import time


content = open('cgi/temp.html', 'r').read()

cookie = Cookie.SimpleCookie()
cookie['heartbeat'] = int(time.time())
cookie['heartbeat']['path'] = '/' 
cookie['heartbeat']['Expires'] = 3600

print cookie
print content

