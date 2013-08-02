var JOSE = JOSE || {};

JOSE.utils = {
    /*** Conversion with UTF-8 strings ***/
    str2abv: function util_str2abv(str) {
        var abv = new Uint8Array(str.length);
        for (var i=0; i<str.length; ++i) {
            abv[i] = str.charCodeAt(i);
        }
        return abv;
    },
    b64Tob64url: function util_b642b64url(str) {
        var x = str.replace(/=/g, '');
        x = x.replace(/+/g, '_');
        x = x.replace(/\//g, '-');
        return x;
    },
    b64urlTob64: function util_b64urlTob64(str) {
        var x = str.replace(/_/g, '+');
        x = x.replace(/-/g, '/');
        switch (x.length % 4) {
        case 0: break;
        case 1: x = x + "==="; break;
        case 2: x = x + "=="; break;
        case 3: x = x + "="; break;
        }
        return x;
    }
}
JOSE.Algorithms = {
    //  Signature algorithms
    HS256: { name:"HMAC", params: {hash: "SHA-256"} },
    HS384: { name:"HMAC", params: {hash: "SHA-384"} },
    HS512: { name:"HMAC", params: {hash: "SHA-512"} },
    RS256: { name:"RSASSA-PKCS1-v1_5", params: { hash: "SHA-256"} },
    RS384: { name:"RSASSA-PKCS1-v1_5", params: { hash: "SHA-384"} },
    RS512: { name:"RSASSA-PKCS1-v1_5", params: { hash: "SHA-512"} },
    ES256: { name:"ECDSA", params: {hash: "SHA-256"} },
    ES384: { name:"ECDSA", params: {hash: "SHA-384"} },
    ES512: { name:"ECDSA", params: {hash: "SHA-512"} },

    //  Key Management Algorithms

    "RSA1_5": { name:"RSAES-PKCS1-v1_5", kt:{name:"RSAES-PKCS1-v1_5"} },
    "RSA-OAEP": { name:"RSA-OAEP", kt:{name:"RSA-OAEP", params: {hash: "SHA-256" }}}, 
    "ECDH-ES": { name:"ECDH", ka:{name: "ECDH"}, kdf:{name:"CONCT", params:{} }},
    "ECDH-ES+A128KW": { name:"ECDH",
                        ka:{name: "ECDH"},
                        kdf:{name: "CONCAT", params:{}},
                        kek: {name: "AES-KW", length: 128 }
                      },
    "ECDH-ES+A256KW": { name:"ECDH",
                        ka:{name: "ECDH"},
                        kdf:{name: "CONCAT", params:{}},
                        kek: {name: "AES-KW", length: 256 }
                      },

    //  Key Wrap algorithms

    "A128KW": { name:"AES-KW", kek: {name:"AES-KW", params: {length:128} }},
    "A256KW": { name:"AES-KW", kek: {name:"AES-WK", params: {length:256} }},
    "A128GCMKW": { name:"AES-GCM", kek: {name:"AES-GCM", params: {} }},
    "A256GCMKW": { name:"AES-GCM", kek: {name:"AES-GCM", params: {} }},

    //  Key Derivation Algorithms

    "PBES2-HS256+A128KW": { name: "PBES2", params:{hash:"SHA-256"},
                            kw: { name: "AES-KW", length: 128 }},
    "PBES2-HS256+A256KW": { name: "PBES2", params:{hash:"SHA-256"},
                            kw: { name: "AES-KW", length: 256 }},

    //  Content Encryption algorithms

    "A128CBC-HS256": { name:"AES-MAC", params: {mac: {name: "HMAC", params: {hash: "SHA-256"}, length:128}, cbc: {name: "AES-CBC", length:128, params: {}}}},
    "A256CBC-HS512": { name:"AES-MAC", params: {mac: {name: "HMAC", params: {hash: "SHA-512"}, length:512}, cbc: {name: "AES-CBC", length:256, params: {}}}},
    "A128GCM": { name:"AES-GCM", params: {length:128, iv:null, tagLength:128}, ivLength:96 },
    "A256GCM": { name:"AES-GCM", params: {length:256, iv:null, tagLength:128}, ivLength:96 },

    //  Special case
    dir: { name:"dir" }
}

JOSE.JWS = function( inputData )
{
    var jsonObj;
    var signerSet = [];
    var that = this;
    var payload;
    var protectHeaderStr = null;
    var protectHeaders = {};
    var unprotectHeaders;

    this.signers = function() { return signerSet };
    this.AddSigner = function(key, algName) {
        var signer = new JOSE.Signer(key, algName);
        signerSet.push(signer);
        signer.SetOwner(that);
        return signer;
    }
    this.protectedHeader = function() {
        if (protectHeaderStr != null) return protectHeaderStr;
        if (protectHeaders == null) return "";
        protectHeaderStr = Base64.encodeURL(Base64.utf8_encode(JSON.stringify(protectHeaders)));
        return protectHeaderStr;
    }
    this.GetContent = function() {
        return payload;
    }
    this.GetPayload = function() {
        return payload;
    }
    this.SetCommonHeader = function(headerName, headerValue) {
        protectHeaders[headerName] = headerValue;
        protectHeaderStr = null;
    }
    this.GetHeader = function(headerName) {
        var x = this.GetProtectedHeader(headerName);
        if (x == null) x = this.GetUnprotectedHeader(headerName);
        return x;
    }
    this.GetProtectedHeader = function(headerName) {
        if (protectHeaders) return protectHeaders[headerName];
        return null;
    }
    this.GetUnprotectedHeader = function(headerName) {
        if (unprotectHeaders) return unprotectHeaders[headerName];
        return null;
    }
    this.SetHeader = function(signerNo, headerKey, headerValue) {
        signerSet[signerNo].SetHeader(headerKey, headerValue);
    }

    this.SetContent = function(contentIn, doBase64) {
        if (typeof(contentIn) !== "string") throw {name:"InvalidArgument"};
        if (typeof(doBase64) == "boolean" && doBase64) {
            payload = Base64.encodeURL(contentIn);
            return;
        }
        for (var i=0; i<contentIn.length; i++) {
            if (contentIn.charCodeAt(i) > 256) throw {name:"InvalidArgument"}
        }
        payload = contentIn;
        return;
    }
    this.GetJSON = function(asString) {
        var returnVal = {};
        if (typeof(asString) !== "boolean") asString = false;
        returnVal["protected"] = protectHeaderStr;
        returnVal["payload"] = payload;
        returnVal["signatures"] = [];
        for (var i=0; i<signerSet.length; i++) {
            returnVal["signatures"][i] = signerSet[i].GetJSON();
        }
        if (asString) {
            returnVal = JSON.stringify(returnVal);
        }
        return returnVal;
    }
    this.GetCompactEncoding = function() {
        var returnVal;
        var t = signerSet[0].GetJSON();
        returnVal = protectedHeaderStr + "." + payload + "." + t["signature"];
        return returnVal;
    }
    this.Sign = function(signForCompact) {
        var i;
        if (typeof(signForCompact) !== "boolean") signForCompact = false;
        if (signerSet.length !== 1) throw { name: "Invalid numbr of signers" }

        if (signForCompact) {
            for (i=0; i<payload.length; i++) {
                var c = payload.charCodeAt(i);
                if ( (c > 127) || (that.map[c] == 0)) throw {name:"Invalid content string"};
            }
            if (protectHeaders == null) protectHeaders = {};
            if (unprotectHeaders) {
                protectHeaders = MergeRecursive(protectHeaders, unprotectHeaders);
                unprotectHeaders = null;
            }
        }
        var all = [];
        for (i=0; i<signerSet.length; i++) {
            all.push(signerSet[i].Sign(signForCompact));
        }
        var d = Q.all(all);
        return d;
    }
    this.Verify = function( fnFindKey ) {
        
        var all = [];
        for (var i=0; i<signerSet.length; i++) {
            all.push(signerSet[i].Verify( fnFindKey ));
        }
        return Q.all(all);
    }


    if (inputData == null) {
        return this;
    }
    else if (typeof inputData == "string") {
        jsonObj = json_parse(inputData);
    }
    else if (typeof inputData == "object") {
        jsonObj = inputData;
    }
    else {
        throw { name:'InvalidParameter' };
    }

    //  Is this a good looking object?

    if (!jsonObj["protected"]) throw { name:'InvalidJOSE' };
    protectHeaderStr = jsonObj["protected"];
    protectHeaders = json_parse(Base64.utf8_decode(Base64.decodeURL(jsonObj["protected"])));
    if (jsonObj["unprotected"]) {
        unprotectHeaders = jsonObj["unprotected"];
    }
    
    payload = jsonObj["payload"];
    var signers = jsonObj["signatures"];
    for (var i=0; i<signers.length; i++) {
        var signer = new JOSE.Signer();
        signer.FromJSON(signers[i]);
        signer.SetOwner(this);
        signerSet.push(signer);
    }

    return this;
}

JOSE.JWS.prototype = {
    //  A-Z a-z 0-9 - _
    map: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
          0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
          0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
}


JOSE.Signer = function(keyIn, sigAlgorithmIn)
{
    var that = this;
    var key;
    var signAlg;
    var owner;
    var headers;
    var signature;
    var verifyResult;


    this.GetOwner = function() { return owner; }
    this.SetOwner = function(newOwner) {
        if (owner !== undefined) throw {name:"Can't change the owner"};
        owner = newOwner;
    }

    this.GetHeader = function(headerName, searchAll) {
        if (typeof(searchAll) != "boolean") searchAll = true;
        if (headers && headers[headerName] != null) return headers[headerName];
        if (searchAll && (owner !== null)) {
            var x = owner.GetProtectedHeader(headerName);
            if (x == null) x = owner.GetUnprotectedHeader(headerName);
            return x;
        }
        return null;
    }
    this.GetJSON = function() {
        var foo = {};
        if (headers) foo["headers"] = headers;
        foo["signature"] = signature;
        return foo;
    }
    this.FromJSON = function(json) {
        signature = json["signature"];
        if (json["header"]) headers = json["header"];
    }
    
    this.GetResult = function() {
        return verifyResult;
    }
    this.SetHeader = function(headerName, headerValue) {
        if (headers == null) headers = {};
        headers[headerName] = headerValue;
    }
    this.Sign = function(forCompacted) {
        if (typeof(forCompacted) != "boolean") throw {name:"Invalid Argument"};
        if (owner == null) throw {name:"InvalidState"}

        if (forCompacted) {
            if (headers !== null) {
                for (var p in headers) {
                    owner.SetCommonHeader(p, headers[p]);
                }
                headers = null;
            }
        }
        
        return window.promisecrypt.sign(signAlg, key)
                .process(JOSE.utils.str2abv(owner.protectedHeader()))
                .process(JOSE.utils.str2abv("."))
                .process(JOSE.utils.str2abv(owner.GetPayload()))
                .finish().then(
                    function(x) {
                        signature = util.b64encode(x);
                    }
                );
    }
    this.Verify = function( fnFindKey ) {
        var d = Q.defer();
        that.result = false;
        var algorithm = JOSE.Algorithms[that.GetHeader("alg")]

        var p = fnFindKey(that, algorithm);
        if (p == null) {
            d.reject(null);
            return d.promise;
        }
        p.then( function (signKey) {
            return window.promisecrypt.verify(algorithm, signKey, util.b64decode(signature))
                .process(JOSE.utils.str2abv(owner.protectedHeader()))
                .process(JOSE.utils.str2abv("."))
                .process(JOSE.utils.str2abv(owner.GetPayload()))
                .finish().then(
                    function ( r) {
                        that.result = true;
                        d.resolve(r);
                    },
                    function ( r) {
                        that.result = false;
                        d.reject();
                    }
                )
            }
        )
        return d.promise;
    }

    
    if (keyIn) {
        key = keyIn;
        if (sigAlgorithmIn != null) {
            signAlg = JOSE.Algorithms[sigAlgorithmIn];
            this.SetHeader("alg", sigAlgorithmIn);
        }
   }

   return this;
}
