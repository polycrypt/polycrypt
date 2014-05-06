Demo Notes
==========

General
-------

1.  All Demo software should be run from a Unix type machine with `bash` and a relatively modern version of `Python` (eg `>= 2.6`).  They have been tested on Linux and Mac OS X machines.  If you are using another platform, you will have to modify some of the installation instructions.  For best results, use a Linux VM.
2.  You must have the PolyCrypt repository checked out for the demos to work (or just possess the source code).  Even demos that do not use PolyCrypt to perform cryptographic operations still use its utility features.
3.  The demos require that you modify your hosts file (typically `/etc/hosts`) to include: `127.0.0.1 polycrypt-test`
4.  You need to run `./tool/webservers.sh src/` from the `PolyCrypt` directory.
5.  You need to run the following command from the App repository:

    python -m SimpleHTTPServer 8002 .

6.  All of the SubtleCrypto demos should be run using our modified version of nightly.
7.  You will need to install the Gemalto drivers on your machine so that Nightly can use the Gemalto smart card.
8.  You will need to load the `.dll/.dylib/.so` Gemalto library into Nightly.  This is found in the `gemalto` section of the DVD.  Open nightly, go to Preferences and then to Security Devices, then you just need to load your `.dll/.dylib/.so` file so Firefox knows where it is.

BasicAuthentication
-------------------

This is our offline version of Token authentication.  You must have the provided Gemalto smart card in the machine for it to work.  You must also be using our distribution of Firefox.  The app will connect to the server that you set up (internet or local apache instance) and then clients can authenticate to the server using the plugged in smart card.

GrayMail
--------

This is our encrypted chat demo.  It is designed to be run from a webserver (can be a local webserver, but not `SimpleHTTPServer` or `CGIHTTPServer`).  It allows two parties to securely communicate using the Web Crypto API (PolyCrypt).  See the readme file in the `../app/graymail` directory for more information.

PolyCrypt / SubtleCrypto
------------------------

This demo showcases the completed functionality of SubtleCrypto as well as to compare how PolyCrypt and SubtleCrypto perform.

Browser as a Second Factor
--------------------------

This is a more detailed example of authenticating to a webserver using either a smart card, or using keys stored in the browser.  This demo does not require a `MySQL` database installation.  It does depend on `bash` and `python`.  This requires the modified version of Firefox and the Gemalto smart card.  Steps:

    $ cd repo-polycrypt
    $ tools/webservers.sh <path-to-app-dir>

    $ cd app/basf/https
    $ ./webserver.py

Browse to `http://localhost:8000` and click on `Browser as a Second Factor`.  This shows a few sample pages that can be reached outside of SSL.  Click `signin` to get to what would be an SSLed connection on a real website.  Since PolyCrypt must be at a different origin, it was not worth setting up an SSL connection back to it for this demo.  However, once the browser does the crypto instead of PolyCrypt, this hurdle is removed.

The top portion of the signin page represents what a user might see.  The bottom portion, below the horizontal line, is additional information, that a developer might care about, shown for demonstration purposes.  On the signin page, you may create a new user, or use a prepopulated one with email:  `usera@amail.com` and password:  `passa`.  Once the email and password are entered, you can click the `software sign` button.  Alternately, if the smart card is plugged in, you can click the `hardware sign` button.  If Firefox prompts you for the password for the smart card, enter `0000` (four zeroes).  You should see various items fill in.  Then, click `sign in`.

The next page might show that you are signed in (if the browser of smart card has previously been registered).  Otherwise, there is one more signin step.  At the top of the page, find the pin that was generated and submit it.

The next page shows the results.  At this point, the user is signed in to the account.  You can create new users and add (keypairs to) browsers for existing users.

You can manually edit the user database in `basf/https/data/users.json`.

Hello-World Demos
-------------

Each of these demos showcases a particular operation (encrypt, sign/verify, hash, chat) that can be accomplished either using PolyCrypt or SubtleCrypto.

