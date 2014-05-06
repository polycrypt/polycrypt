import MySQLdb
from dbparams import myHost, myUser, myPasswd, myDb

db = MySQLdb.connect(host=myHost, user=myUser, passwd=myPasswd, db=myDb)
cursor = db.cursor()

#drop the tables
cursor.execute("drop table waiting;")

db.close()
