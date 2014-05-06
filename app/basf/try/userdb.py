#!/usr/bin/env python

import json
import sys

''' A test for the concept of serializing user accounts.
Writes to a tmp file and reads back from it.

in python:
    user = { username: <username>, k: v, ... }
    users = { username: user, ... }

in json file:
    an object mapping usernames to user dicts
    {
        username: user, ...
    }
'''

def add_dummy_users():
    users = {}
    users['user1@example.com'] = {
            'username': 'user1@example.com',
            'password': 'pass1234',
            'last_signin':  'asdf',
    }

    users['user2@example.com'] = {
            'username': 'user2@example.com',
            'password': 'pass5678',
            'last_signin':  'qwer',
    }

    return users

def main(filename='users.json'):
    users = add_dummy_users()
    print json.dumps(users, indent=4, separators=(',', ': '))
    print

    print 'write users to file...'
    try:
        with open(filename, 'w') as fp:
            json.dump(users, fp, indent=4, separators=(',', ': '))
    except IOError as err:
        print err

    print '\nread users from file...'
    users = {}
    try:
        with open(filename, 'r') as fp:
            users = json.load(fp)
    except IOError as err:
        print err

    print '\nusers:'
    print json.dumps(users, indent=4, separators=(',', ': '))

if __name__ == '__main__':
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        main()

