#!/usr/bin/python

import cgi, cgitb
import jinja2
import random
import os
import MySQLdb
from dbparams import myHost, myUser, myPasswd, myDb
from Crypto.Hash import SHA

cgitb.enable()

jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

form = cgi.FieldStorage()

#All form data
waitingId = form.getvalue("waitingId")  #The "request" identifier for this connection

query = """
        select nonce, signature
        from waiting
        where waitingId = %s;"""

db = MySQLdb.connect(myHost, myUser, myPasswd, myDb)
cursor = db.cursor()

#Get the supposedly signed nonce, based on "request" identifier
cursor.execute(query, (waitingId));
result = cursor.fetchone()
myNonce = result[0]
myHash = SHA.new()
myHash.update(str(result[0]))
myHash = myHash.hexdigest()
mySignature = result[1]

print "Content-type:text/html\r\n\r\n"
template_vals = {}
template_vals.update({"myNonce":myNonce})
template_vals.update({"myHash":myHash})
template_vals.update({"mySignature":mySignature})

template = jinja_environment.get_template("forbidden.html")
print template.render(template_vals)

#Cleanup
db.close()

