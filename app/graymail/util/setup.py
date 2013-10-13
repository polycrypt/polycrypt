import MySQLdb
from dbparams import myHost, myUser, myPasswd, myDb

#Create the two tables required for operation

db = MySQLdb.connect(host=myHost, user=myUser, passwd=myPasswd, db=myDb)
cursor = db.cursor()

"""
roomId --> the unique number for the chat room
user1 --> the number of the first user to connect to the chat
user2 --> the number of the second user to the connect to the chat
"""

rooms = """ 
        create table rooms
        (roomId int not null primary key,
        user1 int,
        user2 int);
        """

"""
roomId --> the unique number for the chat room
userId --> the number of the user
messages --> messages from this user *for the other* user in the room
"""

users = """
        create table users
        (roomId int not null,
        userId int not null,
        messages text);
        """

cursor.execute(rooms)
cursor.execute(users)

db.close()
