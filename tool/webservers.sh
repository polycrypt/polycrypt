#!/bin/bash

#
# start 2 http servers for polycrypt, both on localhost
# server 1 is on port APP_PORT
# server 2 is on port POLYCRYPT_PORT
# both server outputs are logged to file in tool/
#

# get the dir of polycrypt
TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
POLYCRYPT_DIR="${TEST_DIR}/../src"

# get the dir of the app to webserve
DEFAULT_DIR="${TEST_DIR}/../app"
APP_DIR=$1
if [ -z "$APP_DIR" ]; then
    if [ -d ${DEFAULT_DIR} ]; then
        APP_DIR=${DEFAULT_DIR}
    else
        echo
        echo "    USAGE:  ${0} <DIR-to-webserve>"
        echo
        exit
    fi
fi
APP_DIR="$( cd ${APP_DIR} && pwd )"

APP_PORT=8000  # so, browse to http://localhost:8000
POLYCRYPT_PORT=8001

# start the http servers
# log their output to files, overwriting old logfiles
echo "starting app server at localhost:${APP_PORT}"
cd ${APP_DIR} && python -m SimpleHTTPServer ${APP_PORT} >${TEST_DIR}/${APP_PORT}.log 2>&1 &
echo "    log to ${TEST_DIR}/${APP_PORT}.log"
echo "starting polycrypt server at localhost:${POLYCRYPT_PORT}"
cd ${POLYCRYPT_DIR} && python -m SimpleHTTPServer ${POLYCRYPT_PORT} >${TEST_DIR}/${POLYCRYPT_PORT}.log 2>&1 &
echo "    log to ${TEST_DIR}/${POLYCRYPT_PORT}.log"

# wait for the user
echo "press <ENTER> to stop servers"
read TMP

# get the PIDs of the servers
APP_PID=`lsof -t -i tcp:8000`
POLYCRYPT_PID=`lsof -t -i tcp:8001`

# kill the webservers
kill ${APP_PID} ${POLYCRYPT_PID} &
wait $!

# warn if webserver might still be running
if [ "x" != "x`ps -ef | grep Simple | grep HTTPServer`" ] ; then
    echo
    echo "    WARNING:  webserver(s) may still be running.  Check manually."
    echo
fi

