#!/usr/bin/python

import sys
import MySQLdb
import cgi, cgitb
import os
from dbparams import myHost, myUser, myPasswd, myDb

cgitb.enable()

#Lookup any messages that may be waiting for a certain user in a room
db = MySQLdb.connect(host=myHost, user=myUser, passwd=myPasswd, db=myDb)

cursor = db.cursor()

storage = cgi.FieldStorage()
roomId = storage.getvalue("roomId")
userId = storage.getvalue("userId")

getOtheruser = """
               select * from rooms where roomId = %s;
               """

cursor.execute(getOtheruser, (int(roomId)))
room = cursor.fetchone()

#we must find the "other" user and see if they have any messages
#queued up for us
if int(userId) == room[1]:
    otherId = room[2]
else:
    otherId = room[1]

if otherId is None:
    success = False
else:
    success = True

if success:
    query = """
            select * from users where roomId = %s and userId = %s;
            """

    cursor.execute(query, (roomId, otherId))
    result = cursor.fetchone()

    if result[2] == None:
        line = ""
    else:
        line = result[2]

    if line is not "":
        #now must reset the messages because we are about to send them all
        cursor.execute("update users set messages = %s where roomId = %s and userId = %s", ("", roomId, otherId))
else:
    line = ""

print "Content-type:text/html\r\n\r\n<html><body>" + str(line) + "</body></html>"
db.close()
