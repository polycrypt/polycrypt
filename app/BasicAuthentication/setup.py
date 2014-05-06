import MySQLdb
from dbparams import myHost, myUser, myPasswd, myDb

db = MySQLdb.connect(host=myHost, user=myUser, passwd=myPasswd, db=myDb)
cursor = db.cursor()

"""
waitingId --> primary key
IP --> IP address of client
nonce --> generated nonce for authentication
"""

waiting = """
        create table waiting
        (waitingId int not null primary key,
        IP text not null,
        nonce int,
        signature text);
        """

cursor.execute(waiting)

db.close()
