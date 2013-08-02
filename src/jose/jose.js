var JOSE = JOSE || {};

/*
* Recursively merge properties of two objects 
*/
function MergeRecursive(obj1, obj2) {

  for (var p in obj2) {
    try {
      // Property in destination object set; update its value.
      if ( obj2[p].constructor==Object ) {
        obj1[p] = MergeRecursive(obj1[p], obj2[p]);

      } else {
        obj1[p] = obj2[p];

      }

    } catch(e) {
      // Property in destination object not set; create it and set its value.
      obj1[p] = obj2[p];

    }
  }

  return obj1;
}



JOSE.ParseFromCompacted = function ( msg )
{
    var elements = msg.split(".");
    var result = {};

    if (elements.length == 3) {
        result["protected"] = elements[0];
        result["signatures"] = [];
        result["signatures"][0] =  {};
        result["signatures"][0]["signature"] = elements[2];
        result["payload"] = elements[1];
        return new JOSE.JWS(result);

    }
    else {
        result["protected"] = elements[0];
        result["iv"] = elements[2];
        result["recipients"] = [];
        result["recipients"][0] = {};
        result["recipients"][0]["encrypted_key"] = elements[1];
        result["ciphertext"] = elements[3];
        result["tag"] = elements[4];

        return new JOSE.JWE(result);
    }

    return result;
}

JOSE.JWE = function( inputData )
{

    var cekAlgorithm;
    var cekKey;

    var iv;
    var protectedHeaderStr = null;
    var protectedHeaders = {};
    var unprotectedHeaders;
    var ciphertextStr;
    var payload;
    var authTag;
    var recipientSet = [];
    var that = this;

    this.recipients = function() { return recipientSet; }
    this.AddRecipient = function(key, algName) {
        var recipient = new JOSE.Recipient(key, algName);
        recipientSet.push(recipient);
        recipient.SetOwner(that);
        return signer;
    }

    this.SetCEKAlgorithm = function(newAlg) {
        cekAlgorithm = newAlg;
        that.SetCommonHeader("enc", newAlg);
    }


    this.protectedHeader = function() {
        if (protectedHeaderStr != null) return protectedHeaderStr;
        if (protectedHeaders == null) return "";
        protectedHeaderStr = Base64.encodeURL(Base64.utf8_encode(JSON.stringify(protectedHeaders)));
        return protectedHeaderStr;
    }
    this.GetContent = function() {
        return payload;
    }
    this.GetPayload = function() {
        return payload;
    }
    this.SetCommonHeader = function(headerName, headerValue) {
        protectedHeaders[headerName] = headerValue;
        protectedHeaderStr = null;
    }
    this.GetHeader = function(headerName) {
        var x = this.GetProtectedHeader(headerName);
        if (x == null) x = this.GetUnprotectedHeader(headerName);
        return x;
    }
    this.GetProtectedHeader = function(headerName) {
        if (protectedHeaders) return protectedHeaders[headerName];
        return null;
    }
    this.GetUnprotectedHeader = function(headerName) {
        if (unprotectedHeaders) return unprotectedHeaders[headerName];
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
        returnVal["protected"] = protectedHeaderStr;
        returnVal["payload"] = util.b64encode(payload);
        returnVal["recipients"] = [];
        for (var i=0; i<recipientSet.length; i++) {
            returnVal["recipients"][i] = recipientSet[i].GetJSON();
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
    this.Encrypt = function(encryptForCompact) {
        var i;
        var all;
        var d = Q.defer();
        var cek = null;
        var ok = true;

        function encryptContent() {
            var all = [];
            
            for (var i=0; i<recipientSet.length; i++) {
                var promise = recipientSet[i].Encrypt(encryptForCompact, that.cekKey);
                all.push(promise);
            }

            var alg = MergeRecursive({}, JOSE.Algorithms[cekAlgorithm]);
            if ("iv" in alg["params"]) {
                if (alg["params"]["iv"] == null) {
                    // alg["params"]["iv"] = window.crypto.getRandomValue(new Uint8Array(alg["ivLength"]));
                    alg["params"]["iv"] = new Uint8Array([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);
                }
            }

            if (that.protectedHeader()) {
                alg["params"]["additionalData"] = JOSE.utils.str2abv(that.protectedHeader());
            }

            var promise = window.promisecrypt.encrypt(JOSE.Algorithms[cekAlgorithm], that.cekKey, JOSE.utils.str2abv(that.GetContent()));
            promise.then(
                function (result) {
                    payload = result;
                }
            )
            all.push(promise);

            Q.all(all).then (
                function() {
                    d.fulfill();
                },
                function() {
                    d.reject();
                }
            );
        }
        
        if (typeof(encryptForCompact) !== "boolean") encryptForCompact = false;

        if (encryptForCompact) {
            if (recipientSet.length !== 1) throw { name: "Invalid number of signers" }
            if (protectedHeaders == null) protectedHeaders = {};
            if (unprotectedHeaders) {
                protectedHeaders = MergeRecursive(protectedHeaders, unprotectedHeaders);
                unprotectedHeaders = null;
            }
        }

        //  Are any of the recipients directly generating the CEK?

        all = [];
        for (i=0; i<recipientSet.length; i++) {
            var promise = recipientSet[i].GetCEK();
            if (promise) {
                promise.then(
                    function( cekDerived ) {
                        if (cek !== null) {
                            d.reject();
                            ok = false;
                        }
                        cek = cekDerived;
                    }
                )
            }
            all.push(promise);
        }
        
        Q.allSettled(all).then(
            function () {
                if (!ok) return;
                
                if ((that.cekKey !== null) && (cek !== null)) {
                    d.reject();
                    return;
                }
                if (that.cekKey != null) {
                    that.cekKey = cek;
                    encryptContent();
                    return;
                }
                window.promisecrypt.generateKey(JOSE.Algorithms[cekAlgorithm]).then(
                    function( cekIn ) {
                        that.cekKey = cekIn;
                        encryptContent();
                        return;
                    },
                    function () {
                        d.reject();
                    }
                )
            }                
        );

        return d.promise;
    }
    
    this.Decrypt = function( fnFindKey ) {
        var all = [];
        var promiseCEK = Q.defer();
        var cekKeyData = null;

        var cekAlg = JOSE.Algorithms[this.GetHeader("enc")];

        for (var i=0; i<recipientSet.length; i++) {
            var x = recipientSet[i].Decrypt( fnFindKey )
            x.then(
                function(x) { cekKeyData = x; return x; }
            );
            all.push(x);
        }

        

        var promise1 = Q.allSettled(all);
        promise1.then(
            function( x ) {
                //  Import the decrypted key
                //  Need to play some games with a new algorithm?

                if (cekKeyData == null) {
                    promiseCEK.reject(x);
                    return;
                }

                var algX = MergeRecursive({}, cekAlg);
                algX["params"]["iv"] = util.b64decode(iv);
                algX["params"]["tag"] = util.b64decode(authTag);
                if (protectedHeaderStr) algX["params"]["additionalData"] = protectedHeaderStr;
                JOSE.promisecrypt.decrypt(cekAlg, cekKeyData, util.b64decode(ciphertextStr)).then (
                    function (plainText) {
                        payload = plainText;
                        promiseCEK.fulfill(plainText);
                        return plainText;
                    },
                    function (x) { promiseCEK.reject(x); }
                );
            },
            function (x) {
                promiseCEK.reject();
            }
        );

        return promiseCEK.promise;
    }
            

    
    //  Parse out the input data and see if we can understand it

    var jsonObj;

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
        throw { name:'InvalidObject' };
    }

    //  Is this a good looking object?

    if (!jsonObj["protected"]) throw { name:'InvalidJOSE' };
    protectedHeaderStr = jsonObj["protected"];
    protectedHeaders = json_parse(Base64.utf8_decode(Base64.decodeURL(protectedHeaderStr)));

    if (jsonObj["unprotected"]) {
        unprotectedHeaders = jsonObj["unprotected"];
    }
    
    ciphertextStr = jsonObj["ciphertext"];

    iv = jsonObj["iv"];
    authTag = jsonObj["tag"];

    var recipients = jsonObj["recipients"];
    for (var i=0; i<recipients.length; i++) {
        var recipient = new JOSE.Recipient();
        recipient.FromJSON(recipients[i]);
        recipient.SetOwner(this);
        recipientSet.push(recipient);
    }

    return this;
}

JOSE.JWE.prototype = {
    get keyManageAlgorithm() {
        return this.data["alg"];
    },
    set keyManageAlgorithm(val) {
        this.data["alg"] = val;
    },
    get encAlgorithm() {
        return this.data["enc"];
    },
    set encAlgorithm(val) {
        this.data["enc"] = val;
    }
}


JOSE.Recipient = function(keyIn, kmAlgorithmIn)
{
    var that = this;
    var key;
    var kmAlgorithm;
    var owner;
    var headers;
    var encryptedKeyStr;
    var cekKey;

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
        foo["encrypted_key"] = encryptedKeyStr;
        return foo;
    }
    
    this.FromJSON = function(json) {
        encryptedKeyStr = json["encrypted_key"];
        if (json["header"]) headers = json["header"];
    }
    
    this.SetHeader = function(headerName, headerValue) {
        if (headers == null) headers = {};
        headers[headerName] = headerValue;
    }

    this.GetCEK = function() {
        return null;
    }

    this.Encrypt = function( forCompact, cek ) {
        if (typeof(forCompact) !== "boolean") throw { name: "Invalid Argument" };
        if (owner == null) throw { name: "Invalid State" };

        if (forCompact) {
            if (headers !== null) {
                for (var p in headers) {
                    owner.SetCommonHeader(p, headers[p]);
                }
                headers = null;
            }
        }

        var algorithm = JOSE.Algorithms[kmAlgorithm];
        if ("kt" in algorithm) {
            return JOSE.promisecrypt.wrapKey("raw", cek, key, algorithm["kt"]).then (
                function(x) {
                    encryptedKeyStr = util.b64encode(x);
                }
            );
        }
        else if ("ka" in algorithm) {
            
        }
        else if ("kek" in algorithm) {
            return JOSE.promisecrypt.wrapKey("raw", cek, key, algorithm["kek"]).then (
                function(x) {
                    encryptedKeyStr = util.b64encode(x);
                }
            );
        }
        else {
        }
    }
            
    this.Decrypt = function( fnFindKey ) {
        var d = Q.defer();
        var algorithm = JOSE.Algorithms[that.GetHeader("alg")];
        var encryptedKey = util.b64decode(encryptedKeyStr);
        var cekAlgorithm = JOSE.Algorithms[this.GetHeader("enc")];

        function ProcessKeyTransport(keyIn) {
            //  Can't have both key transport and key agree

            if ("ka" in algorithm) {
                d.reject(null);
            }
            
            JOSE.promisecrypt.unwrapKey("raw", encryptedKey, keyIn, algorithm["kt"], cekAlgorithm).then(
                function( keyValue ) {
                    if ("kdf" in algorithm) {
                        ProcessKDF(keyValue);
                    }
                    else {
                        d.fulfill(keyValue);
                    }
                },
                function (keyValue) {
                    d.reject(null);
                }
            )
        }

        function ProcessKeyAgree(keyIn) {
            var theirKey = GetHeader('epku');
            if (theirKey === null) d.reject();

            var kdfAlg = Merge({}, JOSE.Algorithm[algorithm["kdf"]]);

            kdfAlg["algorithmId"] = cekAlgorithm["name"];
            kdfAlg["partyUInfo"] = GetHeader("partyUInfo");
            kdfAlg["partyVInfo"] = GetHeader("partyVInfo");

            JOSE.promisecrypt.secretAgreement(keyIn, theirKey, JOSE.Algorithms[algorithm['ka']], kdfAlg).then(
                function( keyValue ) {
                    var kekAlg = Merge({}, JOSE.Algorithm[algorithm["kek"]]);

                    JOSE.promisecrypt.deriveKey(kdfAlg, keyValue, kekAlg).then(
                        function (keyIn) {
                            ProcessKeyWrap(keyIn);
                        },
                        function () { d.reject(); }
                    )
                },
                function() { d.reject(); }
            );
        }

        function ProcessKDF(keyIn) {
        }

        function ProcessKeyWrap(keyIn) {
            JOSE.promisecrypt.unwrapKey("raw", encryptedKey, keyIn, algorithm["kek"], cekAlgorithm).then(
                function (keyValue ) {
                    d.fulfill(keyValue);
                },
                function() {d.reject()}
            )
        }

        //
        // go back to the caller to find this key
        //

        var p = fnFindKey(that, algorithm);
        if (p == null) {
            d.reject(null);
            return d.promise;
        }

        p.then(
            //
            // A key was found try and use it
            //

           function (kmKey) {
               //  Run some complicated logic to figure out what setup of operations need to be done in order to 
               //  
               //  If this is a key transport algorithm - en we can decrypt it and go to the next step.

               if ("kt" in algorithm) {
                   ProcessKeyTransport(kmKey);
               }
               else if ("ka" in algorithm) {
                   ProcessKeyAgreement(kmKey);
               }
               else if ("kek" in algorithm) {
                   ProcessKeyWrap(kmKey);
               }
               else {
                   //  I don't know how to start processing this key type
                   d.reject(null);
               }
           }
        );

        return d.promise;
    }

    //  Process the input parameters

    if (keyIn) {
        key = keyIn;
        kmAlgorithm = kmAlgorithmIn;
        this.SetHeader("alg", kmAlgorithmIn);
    }
    
    return this;
}
