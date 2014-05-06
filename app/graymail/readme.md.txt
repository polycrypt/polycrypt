GrayMail Encrypted Chat
=======================

GrayMail allows two peers to send encrypted messages using WebRTC Data Connections.  It provides end-to-end encryption using AES-GCM-128.  One user will access the chat client.  They will be redirected to a chat room with a specific id number.  They should copy this link and send it to the person that they want to chat with using some other chat mechanism such as gchat or facebook chat.  Each user can enter a username (their messages will be displayed as coming from this name) and a password.  This password serves to authenticate the users to each other.  If two people who want to communicate enter the same chat room but use different passwords, they will be unable to communicate.  These passwords are NOT required.  

#### Requirements

As of 8/14/2013, Google Chrome and Mozilla Firefox are supported.

As of 9/18/2013, Mac OS X 10.7.5 and Ubuntu 12.04-64 bit are supported and tested, but other versions should work.

Each user of Graymail must use the same browser.

* Firefox <--> Firefox (works)
* Chrome <--> Chrome (works)
* Chrome <--> Firefox (does NOT work)

As of 8/14/2013, Firefox and Chrome implement different versions of the signaling protocol required for WebRTC DataConnections, which is why the same browser must be used at each client end.  Different versions of each browser should work, assuming that WebRTC is enabled and supported in the specific version.

GrayMail uses Polycrypt which implements a recent draft of the Web Crypto API specification (early Summer, 2013).  More recently, Netflix developed nfCrypto which implements the same spec.  Graymail automatically detects if nfCrypto is installed and will seamlessly switch to using this API for some of the cryptographic operations required for the client.  If nfCrypto is not detected, the application will use Polycrypt for all operations.  Please read up on [Polycrypt](https://www.polycrypt.net) for more information and remember that there are serious issue with using pure JavaScript libraries to perform crypto on the web.    

To use Graymail with nfCrypto:

* Use 64-bit Ubuntu 12.04
* Install [NfWebCrypto](https://github.com/Netflix/NfWebCrypto)
* Use Google Chrome to access Graymail (launched from NfWebCrypto, using the proper launch script)

#### Bugs

As of 9/25/13, there is a small chance that two clients cannot connect via WebRTC.  This is most likely due to the fact that when messages are queued in the DB, the CGI script will send these messages to the client and then remove those messages from the DB.  However, after the queued messages are read but before sent out, the client may have sent another message to the server and inserted into the DB.  Precisely then, the DB sends out the messages (does not include the new one) and deletes the saved messages (includes the new one), so the new message is never received by the other peer.

#### Protocol

Optional pre-shared secret.  If none specified, use default value.

    Client 1 --> ephemeral RSA public key 1 --> Client 2
    Client 1 <-- ephemeral RSA public key 2 <-- Client 2

Clients generate random 32-bit nonces.

    Client 1 --> PUB_ENC_CLIENT2RSA(nonce1) --> Client 2
    Client 1 <-- PUB_ENC_CLIENT1RSA(nonce2) <-- Client 2

Clients decrypt the received nonces.  
Clients generate a shared symmetric AES-GCM key:  

    Key K = PBKDF2(secret, SHA1(nonce1) ^ SHA1(nonce2), 2048)

#### Cryptography notes

Ephemeral keys provide forward secrecy.  

Pre-shared secret used for authentication.  

#### *** Known Issue ***

A malicious client can wait to receive a hashed nonce from the other peer, and send back that exact hashed nonce so

    SHA1(nonce1) ^ SHA1(nonce2) = 0x0...0

This is taken care of by making sure that

    SHA1(nonce1) != SHA1(nonce2)

If this happens, the client will "self destruct" and delete almost all objects required for communication and immediately alerts the user.  The odds of this accidentally happening are negligibly small.

#### Implementation Details

Encrypted Message Transmission Format = 

    B64(IV) : B64(AES-GCM cipher output) : B64(additionalData)

#### Source Files

- `chat.html` --> HTML / CSS / JavaScript to handle the user-client interactions
- `chat.py` --> Python CGI to let users create and join rooms
- `dbparams.py` --> KEEP THIS SECRET!  Contains your MySQL login information

- `js/adapter.js` --> Google code to handle WebRTC variable renaming conventions between Firefox and Chrome
- `js/rtc2.js` --> sets up the WebRTC connection and handles cryptographic operations
- `js/nf/nfcrypto.js` --> loads the Netflix Crypto wrappers
- `js/nf/nfutil.js` --> loads the Netflix Crypto utility library
- `js/polycrypt/*` --> all necessary APIs for Polycrypt to function

- `py/dbparams.py` --> KEEP THIS SECRET!  Contains your MySQL login information
- `py/index.html` --> Default page to stop users from exploring your directory
- `py/logout.py` --> Logs a user out of the chat service (removes their rows from the DB)
- `py/message.py` --> Used to send messages from the server to the client (webrtc information)
- `py/update.py` --> Used to send messages from the client to the server (webrtc information)

- `util/reset.py` --> KEEP THIS SECRET!  Empty all tables in the DB
- `util/reset.sh` --> KEEP THIS SECRET!  Shell script used by the cron job to reset the tables
- `util/resetcron.txt` --> KEEP THIS SECRET!  The cron job to register with crontab
- `util/setup.py` --> KEEP THIS SECRET!  Setup the tables for the server

#### Installation Instructions

1.  Have a web server and MySQL server up and running
2.  Create a database called "goliath" (or something else) on your MySQL server
3.  Put all of the source files on your webserver (`license.txt`, `chat.html`, `chat.py`, `js/*`, `py/*`, `util/*`)
4.  Make sure all file permissions are setup correctly (Especially the "KEEP THIS SECRET!" files)
5.  Modify `dbparams.py` to include your MySQL server address, username, password and DB name.  There are two of these files.  
6.  Run `../util/setup.py` to create the appropriate database tables
7.  Register the cron job `../util/resetcron.txt` --> Cleans up the database
8.  Direct users to `http://www.your-web-server.com/chat.py`

