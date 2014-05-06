#!/usr/bin/python

import cgi, cgitb
import jinja2
import random
import os
import MySQLdb
from dbparams import myHost, myUser, myPasswd, myDb
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 
import base64

cgitb.enable()

jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

form = cgi.FieldStorage()

#All form data is Base 64 (except waitingId)
spki = form.getvalue("spki")    #Get the browser's SubjectPublicKeyInfo
sig = form.getvalue("sig")      #The PKCS#1v1.5 encoded signature
waitingId = form.getvalue("waitingId")  #The "request" identifier for this connection

query = """
        update waiting
        set signature = %s
        where waitingId = %s;"""

db = MySQLdb.connect(myHost, myUser, myPasswd, myDb)
cursor = db.cursor()

cursor.execute(query, (sig, waitingId))

query = """
        select nonce
        from waiting
        where waitingId = %s;"""

#Get the supposedly signed nonce, based on "request" identifier
cursor.execute(query, (waitingId));
result = cursor.fetchone()

#Retain a Base-64 and binary signature
sigB64 = sig
sigAscii = base64.b64decode(sig, "-_")

#Hash the nonce for this login attempt
h = SHA.new()
h.update(str(result[0]))

#Import the RSA key from the provided SPKI
key = RSA.importKey(base64.b64decode(spki, "-_"))

#Verifier object to verify the signature and hash
verifier = PKCS1_v1_5.new(key)

if (verifier.verify(h, sigAscii)):
    print "Content-type:text/html\r\n\r\n"
    print "<html>authenticated.py</html>"
else:
    print "Content-type:text/html\r\n\r\n"
    print "<html>forbidden.py</html>"

#Cleanup
db.commit()
db.close()

