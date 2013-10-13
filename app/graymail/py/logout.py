#!/usr/bin/python

import MySQLdb
import cgi, cgitb
import os, sys
from dbparams import myHost, myUser, myPasswd, myDb

#Log users out on webrtc negotiation or page exit
cgitb.enable()

db = MySQLdb.connect(myHost, user=myUser, passwd=myPasswd, db=myDb)

cursor = db.cursor()

storage = cgi.FieldStorage()

roomId = storage.getvalue("roomId")
userId = storage.getvalue("userId")

cursor.execute("delete from rooms where roomId = %s;", (roomId))
cursor.execute("delete from users where roomId = %s and userId = %s;", (roomId, userId))

db.close()

print "Content-Type:text/html\r\n\r\n"
print "<html><body></body></html>"
