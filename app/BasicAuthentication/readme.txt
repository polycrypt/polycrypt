This demonstrates our basic authentication app 

BasicAuthentication will authenticate a client to a webserver using RSA PKCS#1v1.5 Sign/Verify.  It will explicitly use a hardware token to perform all cryptographic operations on the client side in lieu of using SubtleCrypto.  This app will only work with the provided hardware token.  This serves as a sample of how hardware authentication can be used on the web.

System Requirements:
Our version of Nightly [client-side] (specifically we need window.crypto.token.*)
MySQL installed [internet or localhost]
MySQL server up and running [internet or localhost]
A table called "goliath" on your MySQL server
A user who can access this table (update dbparams.py with this user information)
You must modify js/polycrypt/polycrypt.js to have the proper backendSource and backendOrigin variables.

If you are posting this demo on a public facing machine, make sure that you have the appropriate permissions for dbparams.py/.pyc.  This file contains sensitive information about your MySQL server.

To setup the proper MySQL tables:
run /setup.py (or reset.sh if your tables are already setup)

You can then copy the source code onto a server of your choosing (local apache instance works) 

http://your-web-server.com/BasicAuthentication/main.py
