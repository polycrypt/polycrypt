#!/usr/bin/env python

import base64
import cgi
import cgitb
import Cookie
import hashlib
import json
import os
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

# allow top level try-except to work, rather than quitting w/err code
cgitb.enable()

SP = '&nbsp;'

def to_long(b64):
    bytes = base64.urlsafe_b64decode(b64)
    val = 0
    for ch in bytes:
        val = (val << 8) + ord(ch)
    return val

def make_nonce(num_bytes=32):
    nonce = ''
    for byte in os.urandom(num_bytes):
        tmp = hex(ord(byte))[2:]
        while len(tmp) < 2:
            tmp = '0' + tmp
        nonce += tmp
    return nonce

def get_success_msg(user, new_or_old):
    msg = ['<div class="user">',
            '<h1>Welcome {}.</h1>'.format(user),
            '<h2>Sign in successful, using {} key.</h2>'.format(new_or_old),
            '</div>']
    return msg

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

def create_user(users, email, pass_plain):
    if email in users.keys():
        return None
    salt = make_nonce()
    pass_hash = get_pass_hash(pass_plain, salt)
    user = {
            'username':  email,
            'pass_hash':  pass_hash,
            'salt':  salt,
            'prev_signins':  [],
            'challenged_pubkeys':  [],
            }
    users[email] = user
    save_users(users)
    return user

def get_form_content():
    '''Return dict of k,v pairs from html form.'''
    form = cgi.FieldStorage(keep_blank_values=True)
    f = {}
    for key in form.keys():
        # Only include the first value for each key.
        f[key] = cgi.escape(form.getfirst(key))
    return f

def get_pass_hash(pass_plain, salt):
    pass_hash = pass_plain + salt
    for _ in range(10000):
        m = hashlib.sha256()
        m.update(pass_hash)
        pass_hash = m.digest()
    pass_enc = ''
    for byte in pass_hash:
        val = hex(ord(byte))[2:]
        while len(val) < 2:
            val = '0' + val
        pass_enc += val
    return pass_enc

def check_sig(key, hexServer, hexClient, sig_b64):
    # convert sig_b64 to str of bytes for verify()
    sig = base64.urlsafe_b64decode(sig_b64)

    # concatenate nonces for hash()
    hexServer = '0'*(8 - len(hexServer)) + hexServer
    hexClient = '0'*(8 - len(hexClient)) + hexClient
    hexmsg = hexServer + hexClient
    msg = ''
    while hexmsg:
        chunk, hexmsg = hexmsg[:2], hexmsg[2:]
        msg += chr(int(chunk, 16))

    try:
        h = SHA.new(msg)
        verifier = PKCS1_v1_5.new(key)
        result = verifier.verify(h, sig)
        return result
    except Exception as err:
        output(str(err) + '<br>')
    return False

def rsakey_from_components(key_n, key_e):
    # convert n,e to Long for RSA.construct()
    key_n = to_long(key_n)
    key_e = to_long(key_e)

    try:
        key = RSA.construct( (key_n, long(key_e)) )
        return key
    except Exception as err:
        output(str(err) + '<br>')

def rand_char(num=1):
    chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    text = ''
    for _ in range(num):
        text += chars[ord(os.urandom(1)) % len(chars)]
    return text

def hash_challenge(ch):
    '''Compute hash of challenge object.'''
    dgstr = hashlib.sha256()
    dgstr.update(ch['username'])
    dgstr.update(ch['ts'])
    dgstr.update(ch['spki_b64'])
    dgstr.update(ch['ip'])
    dgstr.update(ch['nonce'])
    return dgstr.hexdigest()

def output(body, cookie=None):
    '''Write an html page with http header.'''
    if isinstance(body, (str, unicode)):
        body = [body]
    http = open('template/generic-http.txt', 'r').readlines()
    if cookie is not None:
        http = [cookie.output()] + http
    head = open('template/generic-head.txt', 'r').read()
    head = head.replace('{{title}}', 'process signin')
    head = head.replace('<!--script-->', show_cookie())
    head = head.split('\n')
    #head_raw = open('template/generic-head.txt', 'r').readlines()
    #head = []
    #for line in head_raw:
    #    head.append(line.replace('{{title}}', 'process signin'))
    tail = open('template/generic-tail.txt', 'r').readlines()
    for line in http + head + body + tail:
        print str(line)

def show_cookie():
    return '''
<script>
function go() {
    document.getElementById('temp').innerHTML += '<br>' + document.cookie;
}
document.onload = go;
</script>
'''

def process():
    body = []
    #body.append('<button type="button" onclick="go()">view cookie</button><br>')
    body.append('<div class="demo">')
    # load info from form
    form = get_form_content()
    #body.append('remote_addr: {}<br>'.format(cgi.escape(os.environ['REMOTE_ADDR'])))
    body.append('Got from form:<br>')
    for k,v in form.items():
        if len(v) > 64:
            v = v[0:10] + ' ... ' + v[-10:]
        body.append('{0}{1}: {2!r}<br>'.format(SP*4, k, v))

    # load users
    users = load_users()
    body.append('Loaded users:')
    for email in users.keys():
        body.append('{0}{1}'.format(SP*2, email))
    body.append('<br>')

    # either create new user in userdb, or check password
    email = form['email']
    if 'new_user' in form.keys():
        if email in users.keys():
            body.append('User "{0}" already in database.<br>'.format(email))
            body.append('</div>')
            output(body)
            return
        else:
            if 'password' in form:
                form_pass = form['password']
            else:
                form_pass = ''
            user = create_user(users, email, form_pass)
            body.append('New user "{0}" created in database.<br>'.format(email))
    else:
        if email not in users.keys():
            body.append('User "{0}" not found in database.<br>'.format(email))
            body.append('</div>')
            output(body)
            return
        else:
            user = users[email]
            body.append('User "{0}" from form found in database.<br>'.format(email))
            # check password v db
            db_pass = user['pass_hash']
            if 'password' in form:
                form_pass = form['password']
            else:
                form_pass = ''
            salt = user['salt']
            form_pass_hash = get_pass_hash(form_pass, salt)

            if db_pass != form_pass_hash:
                body.append('Incorrect password.')
                body.append('</div>')
                output(body)
                return
            body.append('Password matches.<br>')

    # get key info from form
    if ('key_n' in form and form['key_n'] != '' and
            'key_e' in form and form['key_e'] != ''):
        key = rsakey_from_components(form['key_n'], form['key_e'])
        spki_b64 = base64.urlsafe_b64encode(key.exportKey('DER'))
    elif 'spki_b64' in form and form['spki_b64'] != '':
        spki_b64 = form['spki_b64']
        spki = base64.urlsafe_b64decode(spki_b64)
        key = RSA.importKey(spki)
    else:
        body.append('Could not get key from form.<br>')
        body.append('</div>')
        output(body)
        return
    body.append('Loaded key from form.<br>')

    # check if sig verifies
    if not check_sig(key, form['nonceServer'], form['nonceClient'], form['sig_b64']):
        body.append('Invalid signature.<br>')
        body.append('</div>')
        output(body)
        return
    body.append('Signature verifies.<br>')

    # is user assoc with pubkey?
    if 'pubkeys' not in user:
        user['pubkeys'] = []
    for pubkey in user['pubkeys']:
        if pubkey['spki_b64'] == spki_b64:
            body = get_success_msg(user['username'], 'existing') + ['<hr>'] + body
            body.append('Username is assoc w/ supplied pubkey.<br>')
            body.append('Setting cookie with user email.<br>')
            cookie_user_email = Cookie.SimpleCookie()
            cookie_user_email['user_email'] = user['username']
            cookie_user_email['user_email']['path'] = '/'
            cookie_user_email['user_email']['Expires'] = 31536000
            cookie_user_email['user_email']['httponly'] = True
            output(body, cookie_user_email)
            return

    # create,show 2nd factor challenge
    body.append('User is not assoc w/ supplied pubkey.<br>')
    challenge_text = rand_char(6)
    challenge = {
            'username':  user['username'],
            'text':  challenge_text,
            'ts':  str(int(time.time())),
            'spki_b64':  spki_b64,
            'ip':  cgi.escape(os.environ['REMOTE_ADDR']),
            'nonce':  make_nonce(32),
            }
    challenge['hash'] = hash_challenge(challenge)
    user['challenged_pubkeys'].append(challenge)

    # save challenge text in user db
    save_users(users)
    # don't send challenge text in cookie
    del challenge['text']

    body.append('</div>')
    user_portion = []
    user_portion.append('<div class="user">')
    user_portion.append('Pretend you got this pin in your email: {}<br>'.format(challenge_text))
    user_portion.append('Submit it to complete registration for this browser or smart card.<br>')
    user_portion.append("<form action='http://localhost:4343/cgi/process_challenge.py' method='post'>" +
            "verification code: <input type='text' name ='text'>" +
            "<input type='submit' value='Submit'> </form>")
    user_portion.append('</div><hr />')
    body = user_portion + body

    # create, set cookie
    cookie = Cookie.SimpleCookie()
    cookie['challenge'] = json.dumps(challenge)
    cookie['challenge']['path'] = '/'
    #cookie['challenge']['secure'] = True
    cookie['challenge']['httponly'] = True
    #print cookie

    output(body, cookie)
    #output(body)

process()

