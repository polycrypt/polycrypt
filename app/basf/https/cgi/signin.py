#!/usr/bin/env python

import Cookie
import json
import os
import random

# location of  userdb
filename = 'data/users.json'

py_error = ''

# get users from db
users = {'---':{},}
try:
    with open(filename, 'r') as fp:
        users = json.load(fp)
except IOError as err:
    py_error += str(err)


content = open('template/signin.html', 'r').read()

# insert page title
content = content.replace('{{title}}', 'Sign in')

# insert user from cookie
user_email = None
try:
    cookie = Cookie.SimpleCookie(os.environ['HTTP_COOKIE'])
    user_email = cookie['user_email'].value
except:
    pass

if user_email:
    content = content.replace('{{value}}', 'value="' + user_email + '"')
else:
    content = content.replace('{{value}}', "value=''")

# insert value of nonce
nonce_server = hex(random.SystemRandom().randint(0, 0xffffffff))[2:]
nonce_server = '0'*(8-len(nonce_server)) + nonce_server
content = content.replace('{{nonce_server}}', nonce_server)

# insert known emails
known_emails = 'known emails:'
for email in sorted(users.keys()):
    known_emails += '&nbsp;&nbsp;{0}'.format(email)
content = content.replace('{{known_emails}}', known_emails)

# show any python errors
content = content.replace('{{py_error}}', py_error)
if py_error == '':
    content = content.replace('{{py_error_display}}', 'display: none')
else:
    content = content.replace('{{py_error_display}}', 'display: block')

print content

