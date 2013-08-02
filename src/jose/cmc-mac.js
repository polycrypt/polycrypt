var JOSE = JOSE || {};

JOSE.CBC_MAC = {
    generateKey: function(algorithm, extractable, keyUsages) {
        if (extractable == null) extractable = false;
        if (keyUsages == null) keyUsages = [];

        var newKey = new JOSE.CBC_MAC.key();
        newKey.extractable = extractable;
        newKey.keyUsages = keyUsages;
        
        var p1 = window.promisecrypt.generateKey(algorithm["params"]["cbc"], extractable, keyUsages);
        p1.then(function(x) { newKey.key_cbc = x; return x; } );

        var p2 = window.promisecrypt.generateKey(algorithm["params"]["mac"], extractable, keyUsages);
        p2.then(function(x) { newKey.key_mac = x; return x; } );

        var pRet = Q.defer();
        
        Q.all([p1, p2]).then(function(x) { pRet.fulfill(newKey); }, function() {pRet.reject();} );

        return pRet.promise;
    },
    exportKey: function (format, key) {
        if (format != "raw") throw { name: "InvalidArg"};
        var pRet = Q.defer();
        var rgCBC;
        var rgMAC;

        var p1 = window.promisecrypt.exportKey("raw", key.key_cbc);
        p1.then( function(x) { rgCBC = x; return x; });

        var p2 = window.promisecrypt.exportKey("raw", key.key_mac);
        p2.then( function(x) { rgMAC = x; return x; });

        Q.all([p1, p2]).then(
            function() {
                var cbcData = new Uint8Array(rgCBC, 0, rgCBC.byteLength);
                var macData = new Uint8Array(rgMAC, 0, rgMAC.byteLength);
                var keyData = new Uint8Array(rgCBC.byteLength + rgMAC.byteLength);

                for (var i=0; i<macData.length; i++) keyData[i] = macData[i];
                for (i=0; i<cbcData.length; i++) keyData[i+macData.length] = cbcData[i];

                pRet.fulfill(keyData);
            },
            function () { pRet.reject(); }
        );

        return pRet.promise;
    },
    importKey: function (format, keyDataIn, algorithm, extractable, keyUsages) {
        var i;
        var keyData = new Uint8Array(keyDataIn.buffer, 0, keyDataIn.byteLength);
        if (format != "raw") throw {name: "InvalidArg"};
        if (keyData.length*8 != algorithm["params"]["cbc"]["length"] + algorithm["params"]["mac"]["length"]) throw {name: "InvalidArg"};
        var newKey = new JOSE.CBC_MAC.key();

        var cekKey = new Uint8Array(algorithm["params"]["cbc"]["length"]/8);
        var macKey = new Uint8Array(algorithm["params"]["mac"]["length"]/8);
        for (i=0; i<macKey.length; i++) macKey[i] = keyData[i];
        for (i=0; i<cekKey.length; i++) cekKey[i] = keyData[i+cekKey.length];

        var p1 = window.promisecrypt.importKey("raw", cekKey, algorithm["params"]["cbc"]["name"], false).then(
            function(x) {
                newKey.key_cbc = x;
                return x;
            }
        );

        var p2 = window.promisecrypt.importKey("raw", macKey,  algorithm["params"]["mac"]["name"], false).then (
            function(x) {
                newKey.key_mac = x;
                return x;
            }
        );

        var pRet = Q.defer();
        Q.all([p1, p2]).then(function(x) { pRet.fulfill(newKey); }, function () { pRet.reject(null); });
        return pRet.promise;
    },
    decrypt: function(algorithm, key, data) {
        algorithm["params"]["cbc"]["params"]["iv"] = algorithm["params"]["iv"];
        var coCEK = window.promisecrypt.decrypt(algorithm["params"]["cbc"], key.key_cbc);
        var coMAC = window.promisecrypt.verify(algorithm["params"]["mac"], key.key_mac, algorithm["params"]["tag"]);
        
        var cop = new JOSE.CBC_MAC.CryptoOperation(algorithm, key, coCEK, coMAC);

        if (algorithm["params"]["additionalData"]) {
            coMAC.process(JOSE.utils.str2abv(algorithm["params"]["additionalData"]));
            cop.aeadLength = algorithm["params"]["additionalData"].length;
            coMAC.process(algorithm["params"]["iv"]);
        }

        cop.decrypt = true;

        if (data) {
            cop.process(data);
            cop.finish();
        }
        return cop.MakePromise(cop);

    },
    encrypt: function(algorithm, key, data) {
        algorithm["params"]["cbc"]["params"]["iv"] = algorithm["params"]["iv"];
        var coCEK = window.promisecrypt.encrypt(algorithm["params"]["cbc"], key.key_cbc);
        var coMAC = window.promisecrypt.digest(algorithm["params"]["mac"], key.key_mac);

        var cop = new JOSE.CBC_MAC.CryptoOperation(algorithm, key, coCEK, coCMAC);

        if (algorithm["params"]["additionalData"]) {
            coMAC.process(util.b64decode(algorithm["params"]["additionalData"]));
            cop.aeadLength = algorithm["params"]["additoinalData"].length;
            coMAC.process(algorithm["params"]["iv"]);
        }

        cop.decrypt = false;

        if (data) {
            cop.process(data);
            cop.finish();
        }
        return cop.MakePromise(cop);
    }
};

JOSE.CBC_MAC.key = function() {
    return this;
}

JOSE.CBC_MAC.CryptoOperation = function(algorithm, key, coCEK, coMAC) {
    this.algorithm = algorithm;
    this.key = key;
    this.coCEK = coCEK;
    this.coMAC = coMAC;
    return this;
};

JOSE.CBC_MAC.CryptoOperation.prototype = {
    MakePromise: function(cop) {
        var d = Q.defer();
        var result;
         var that = this;

        d.promise.process = JOSE.CBC_MAC.CryptoOperation.prototype.process;
        d.promise.finish = JOSE.CBC_MAC.CryptoOperation.prototype.finish;

        this.coCEK.then(
            function(x) {
                result = x;
                if (!that.decrypt) {
                    that.coMAC.process(result);
                }
                
                var len = new Uint8Array(8);
                var len2 = that.aeadLength * 8;
                
                for (var i=7; i>=0; i--) {
                    len[i] = len2 & 255;
                    len2 = len2/256;
                }
                that.coMAC.process(len);
                that.coMAC.finish();
                
                return x;
            },
            function () {
                d.reject();
            }
        );

        this.coMAC.then(
            function(x) {
                if (x) d.fulfill(result);
                else d.reject();
                return x;
            },
            function() {
                d.reject();
            }
        );

        this.promise = d.promise;
        return this.promise;
    },

    process: function(data) {
        this.coCEK.process(data);
        if (this.decrypt) this.coMAC.process(data);
        return this.promise;
    },

    finish: function() {
        this.coCEK.finish();
        return this.promise;
    }
};
    
