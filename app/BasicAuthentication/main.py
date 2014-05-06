#!/usr/bin/python

import cgi, cgitb
import jinja2
import random
import os
import MySQLdb
from dbparams import myHost, myUser, myPasswd, myDb

cgitb.enable()

jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

#Setup a new user in the database
def setupWaiting(cursor, waitingId, nonce):
    query = """insert into waiting (waitingId, IP, nonce) values (%s, %s, %s);"""
 
    cursor.execute(query, (waitingId, os.environ["REMOTE_ADDR"], nonce))

#Generate a random id number
def generateRandom(size):
    word = ""
    for i in range(size):
        word += random.choice("123456789")

    return word

"""
form = cgi.FieldStorage()
roomId = form.getvalue()
"""

db = MySQLdb.connect(myHost, myUser, myPasswd, myDb)
cursor = db.cursor()

waitingId = generateRandom(9)
nonce = generateRandom(9)
setupWaiting(cursor, waitingId, nonce)

print "Content-type:text/html\r\n\r\n"
template_vals = {}
template_vals.update({"nonce":nonce})
template_vals.update({"id":waitingId})

template = jinja_environment.get_template("main.html")
print template.render(template_vals)

db.commit()
db.close()

