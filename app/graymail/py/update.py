#!/usr/bin/python

import sys
import MySQLdb
import cgi, cgitb
import os
from dbparams import myHost, myUser, myPasswd, myDb

#post a message to the database
cgitb.enable()

db = MySQLdb.connect(host=myHost, user=myUser, passwd=myPasswd, db=myDb)

cursor = db.cursor()

storage = cgi.FieldStorage()
msg = storage.getvalue("msg")
roomId = storage.getvalue("roomId")
userId = storage.getvalue("userId")

#Get the messages for the user
cursor.execute("select * from users where userId = %s and roomId = %s;", (int(userId), int(roomId)))
result = cursor.fetchone()

prev = result[2]
if prev is None:
    prev = msg
else:
    prev = prev + msg

query = """
        update users set messages = %s where userId = %s and roomId = %s;
        """

cursor.execute(query, (prev, userId, roomId))

db.close()

print "Content-Type:text/html\r\n\r\n"
print "<html><body>Updated messages: " + str(prev) + "</body></html>"

