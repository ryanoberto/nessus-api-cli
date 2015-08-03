#!/usr/bin/python
import sqlite3
conn = sqlite3.connect('status.db')
c = conn.cursor()

c.execute('''CREATE TABLE scans
             (uuid)''')

conn.commit()
conn.close()
