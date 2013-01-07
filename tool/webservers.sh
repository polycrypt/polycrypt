#!/bin/bash

#
# start 2 http servers for polycrypt, both on localhost
# server 1 is on port APP_PORT
# server 2 is on port POLYCRYPT_PORT
# both server outputs are logged to file
#

TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
APP_DIR="${TEST_DIR}/../src/app"
POLYCRYPT_DIR="${TEST_DIR}/../src"

APP_PORT=8000
POLYCRYPT_PORT=8001

# start the http servers
# log their output to files, overwriting old logfiles
echo "starting app server at localhost:${APP_PORT}"
cd ${APP_DIR} && python -m SimpleHTTPServer ${APP_PORT} >${TEST_DIR}/${APP_PORT}.log 2>&1 &
APP_PPID=$!
echo "logfile:  ${TEST_DIR}/${APP_PORT}.log"
echo "starting polycrypt server at localhost:${POLYCRYPT_PORT}"
cd ${POLYCRYPT_DIR} && python -m SimpleHTTPServer ${POLYCRYPT_PORT} >${TEST_DIR}/${POLYCRYPT_PORT}.log 2>&1 &
POLYCRYPT_PPID=$!
echo "logfile:  ${TEST_DIR}/${POLYCRYPT_PORT}.log"

# get the PIDs of the servers
APP_PID=`ps -f | egrep "\d+\ +\d+\ +${APP_PPID}" | sed -e 's/[ ] */ /g' | cut -f 2 -d ' ' -`
POLYCRYPT_PID=`ps -f | egrep "\d+\ +\d+\ +${POLYCRYPT_PPID}" | sed -e 's/[ ] */ /g' | cut -f 2 -d ' ' -`

# wait for the user
echo "press <ENTER> to stop servers"
read TMP
# kill the servers
kill ${APP_PID} ${POLYCRYPT_PID} ${APP_PPID} ${POLYCRYPT_PPID}

sleep 1

if [ "x" != "x`ps -ef | grep Simple | grep HTTPServer`" ] ; then
    echo
    echo "WARNING:  webserver(s) may still be running.  Check manually."
fi

