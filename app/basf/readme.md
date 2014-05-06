terminal 1:

    $ cd polycrypt
    $ ./tool/webservers.sh .

terminal 2:

    $ cd app/basf/http
    $ ./webserver.py

terminal 3:

    $ cd app/basf/https
    $ ./webserver.py

dependency:  Some default `pycrypto` installs are insufficient.  In terminal 3
you may see an error like `no module named Signature`.  In that case, you may
need to manually install the full package:

    $ sudo pip install --upgrade pycrypto

in browser:

    http://localhost:8002

