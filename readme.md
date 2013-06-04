PolyCrypt - A pure JS implementation of the WebCrypto API
=========================================================

This project is an implementation of the W3C WebCrypto API. 

For full details, see [our website](http://polycrypt.net/)

Quick Start
-----------

```
> echo 127.0.0.1  polycrypt-test >>/etc/hosts
> cd $POLYCRYPT_ROOT
> ./tool/webservers.sh
> # Load http://polycrypt-test:8000/ in your favorite browser
```


## Successfully tested in the following browsers

* Chrome  [ Desktop, Android, iOS ]
* Firefox  [ Desktop, Android ] 
* Safari  [ Desktop, iOS ]
* Internet Explorer  [ Desktop, Phone ]
* Opera  [ Desktop ]
* iCab 

## Currently thought to not work these browsers

* Default Android browser
* Opera Mini
* Versions of IE < 10

## Known issues

* Uses `window.polycrypt` instead of `window.crypto.subtle`, because some browsers don't allow extensions to `window.crypto.subtle`.
* The following algorithms in the WebCrypto specification are not currently supported: RSA-OAEP, RSA-PSS, ECDSA, ECDH, Diffie-Hellman, Concat KDF
* Safari: Does not work in Private Browsing Mode
* Firefox: Does not work if cookies set to "Ask me"
* Appears not work with NoScript (even when disabled for site)
* Cannot be used from local pages (on disk) due to need for postMessage

