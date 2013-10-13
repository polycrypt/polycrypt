#!/usr/bin/python

import cgi, cgitb
import jinja2
import random
import os
import MySQLdb
from dbparams import myHost, myUser, myPasswd, myDb

cgitb.enable()

jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

#Get a room based on the roomId
def getRoom(cursor, id):
    query = """
            select * from rooms where roomId = %s;
            """

    cursor.execute(query, (id))
    return cursor.fetchone()

#Add a room to the database based on roomId
def addRoom(cursor, roomId):
    query = """
            insert into rooms (roomId) values (%s);
            """
    cursor.execute(query, (roomId))

#Update a room in the database with the new userId
def updateRoom(cursor, roomId, userId):
    room = getRoom(cursor, roomId)
    if room is None:
        return True

    if room[1] == None:
        query = """
                update rooms set user1 = %s where roomId = %s;
                """
    elif room[2] == None:
        query = """
                update rooms set user2 = %s where roomId = %s;
                """
    else:
        return True

    cursor.execute(query, (userId, roomId))

    setupUsers(cursor, roomId, userId)
    return False

#Setup a new user in the database
def setupUsers(cursor, roomId, userId):
    query = """insert into users (roomId, userId) values (%s, %s);"""

    cursor.execute(query, (roomId, userId))

#Get the size of the current room
def getSize(cursor, roomId):
    room = getRoom(cursor, roomId)
    count = 0
    if room[1] is not None:
        count = count + 1
    if room[2] is not None:
        count = count + 1

    return count

#Generate a random id number
def generateRandom(size):
    word = ""
    for i in range(size):
        word += random.choice("123456789")

    return word

form = cgi.FieldStorage()
roomId = form.getvalue("r")

ready = False

#If they navigated to the page without a roomId, generate one and redirect
if roomId == None:
    ready = True
    db = MySQLdb.connect(host=myHost, user=myUser, passwd=myPasswd, db=myDb)
    cursor = db.cursor()
    room = generateRandom(7)
    addRoom(cursor, room)
    db.close()
    print "Location:?r=" + room + "\r\n\r\n"

#If they have a room number, perform DB operations and render page
if not ready:
    db = MySQLdb.connect(host=myHost, user=myUser, passwd=myPasswd, db=myDb)
    cursor = db.cursor()

    currentRoom = getRoom(cursor, roomId)
    userId = generateRandom(5)
    fail = updateRoom(cursor, roomId, userId)

    #If the room is full (or any other failure), redirect them to a new room in 3 seconds
    if fail:
        print "content-Type:text/html\r\n\r\n"
        print "<html><title>GrayMail</title><h2>The room you are trying to access is currently full.  You will be directed shortly."
        print "</h2><script type='text/javascript'>setTimeout(function() { window.location = 'chat.py' }, 3000);</script></html>"
    else:
        print "Content-type:text/html\r\n\r\n"
        count = getSize(cursor, roomId)

        template_vals = {}
        template_vals.update({"roomId":roomId})
        template_vals.update({"userId":userId})
        template_vals.update({"count":count})

        template = jinja_environment.get_template("chat.html")
        print template.render(template_vals)

    db.close()

