#!/usr/bin/env python

import cgi
import cgitb
import Cookie
import hashlib
import json
import os
import time

# allow top level try-except to work, rather than quitting w/err code
cgitb.enable()

SP = '&nbsp;'

def toLong(b64):
    bytes = base64.b64decode(b64, '-_')
    val = 0
    for ch in bytes:
        val = (val << 8) + ord(ch)
    return val

def load_users(filename='data/users.json'):
    users = {}
    try:
        with open(filename, 'r') as fp:
            users = json.load(fp)
    except IOError as err:
        err = err.split('\n')
        lines = []
        for line in err:
            lines.append(line + '<br>')
        output(lines)
    return users

def save_users(users, filename='data/users.json'):
    try:
        with open(filename + '.tmp', 'w') as fp:
            json.dump(users, fp, indent=4, separators=(',', ': '))
        os.rename(filename + '.tmp', filename)
    except IOError as err:
        print err

def get_form_content():
    '''Return dict of k,v pairs from html form.'''
    form = cgi.FieldStorage(keep_blank_values=True)
    f = {}
    for key in form.keys():
        # Only include the first value for each key.
        f[key] = cgi.escape(form.getfirst(key))
    return f

def hash_challenge(ch):
    dgstr = hashlib.sha256()
    dgstr.update(ch['username'])
    dgstr.update(ch['ts'])
    dgstr.update(ch['spki_b64'])
    dgstr.update(ch['ip'])
    dgstr.update(ch['nonce'])
    return dgstr.hexdigest()

def output(body, cookie=None):
    '''Write an html page with http header.'''
    if isinstance(body, str):
        body = [body]
    http = open('template/generic-http.txt', 'r').readlines()
    if cookie is not None:
        http = [cookie.output()] + http
    head = open('template/generic-head.txt', 'r').read().replace('{{title}}', 'process challenge').split('\n')
    tail = open('template/generic-tail.txt', 'r').readlines()
    for line in http + head + body + tail:
        print str(line)

def process():
    body = []
    # load info from form
    form = get_form_content()
    body.append('<div class="demo">')
    body.append('Got from form:<br>')
    for k,v in form.items():
        body.append('{0}{1}: {2!r}<br>'.format(SP*4, k, v))

    # read cookie
    try:
        cookie_string = os.environ.get('HTTP_COOKIE', '')
        if not cookie_string:
            body.append('Got no cookie.<br>')
            output(body)
            return
        cookie = Cookie.SimpleCookie()
        cookie.load(cookie_string)
    except Cookie.CookieError as err:
        raise err

    body.append('Got cookie:<br>')
    challenge = json.loads(cookie['challenge'].value)
    for k,v in challenge.items():
        if len(v) > 40:
            v = v[0:10] + ' ... ' + v[-10:]
        body.append('{0}{1}: {2!r}<br>'.format(SP*4, k, v))
    username = challenge['username']
    ts = challenge['ts']
    spki_b64 = challenge['spki_b64']
    ip = challenge['ip']
    nonce = challenge['nonce']

    _challenge = {
            'username':  username,
            'text':  form['text'],
            'ts':  ts,
            'spki_b64':  spki_b64,
            'ip':  ip,
            'nonce':  nonce,
            }

    if not hash_challenge(_challenge) == challenge['hash']:
        body.append('Challenge cookie does not match.<br>')
        output(body)
        return

    body.append('Challenge cookie matches.<br>')

    if not form['text'] == _challenge['text']:
        body.append('Challenge failed.<br>')
        output(body)
        return

    body.append('Challenge succeeded.<br>')

    # load users
    users = load_users()
    body.append('Loaded users:<br>')
    for user in users:
        body.append('{0}{1}<br>'.format(SP*4, user))

    email = _challenge['username']

    # check for user in userdb
    if email not in users.keys():
        body.append('User "{0}" not in database.<br>'.format(email))
        output(body)
        return

    user = users[email]
    body.append('User "{0}" found in database.<br>'.format(email))

    # delete old challenged_pubkeys
    #TODO: put timeout in settings file.  make this a util function
    HOUR = 3600
    deleted_one = True
    while 0 < len(user['challenged_pubkeys']) and deleted_one:
        deleted_one = False
        for chpk in user['challenged_pubkeys']:
            if time.time() - int(chpk['ts']) > HOUR:
                body.append('Deleting old challenged_pubkey.<br>')
                user['challenged_pubkeys'].remove(chpk)
                deleted_one = True
                break

    # add key to user
    for key in user['pubkeys']:
        if key['spki_b64'] == _challenge['spki_b64']:
            body.append('</div>')
            user_portion = []
            user_portion.append('<div class="user">')
            user_portion.append('<h1>Welcome {}.</h1>'.format(user['username']))
            user_portion.append('<h2>This key is already assigned to you.</h2>')
            user_portion.append('</div><hr />')
            body = user_portion + body
            output(body)
            return

    newkey = {
            'spki_b64': _challenge['spki_b64'],
            }
    user['pubkeys'].append(newkey)
    # delete challenged_pubkey
    for chpk in user['challenged_pubkeys']:
        if chpk['spki_b64'] == newkey['spki_b64']:
            body.append('Deleting challenged_pubkey.<br>')
            user['challenged_pubkeys'].remove(chpk)
            break
    body.append('</div>')

    save_users(users)

    user_portion = []
    user_portion.append('<div class="user">')
    user_portion.append('<h1>Welcome {}.</h1>'.format(user['username']))
    user_portion.append('<h2>Your new key has been added to your account.</h2>')
    user_portion.append('</div><hr />')
    body = user_portion + body

    output(body)

process()

