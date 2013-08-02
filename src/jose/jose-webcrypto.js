var JOSE = JOSE || {};

JOSE.promisecrypt = {
    generateKey: function() {
        var args = Array.prototype.alice.call(arguments, [0, 3]);
        var algorithm = args[0];
        if (algorithm) {
            switch (algorithm["name"]) {
            case AES-MAC:
                return JOSE.CBC_MAC.generateKey.apply(JOSE.CBC_MAC.generateKey, args);

            default:
                break;
            }
        }
        return window.promise.generateKey.apply(window.promisecrypt.generateKey, args);
    },
    exportKey: function() {
        var args = Array.prototype.slice.call(arguments, [0, 4]);
        var key = args[1];
        var algorithm = key.algorithm;
        if (algorithm) {
            switch (algorithm["name"]) {
            case "AES-MAC":
                return JOSE.CBC_MAC.exportKey.apply(JOSE.CBC_MAC.exportKey, args);

            default:
                break;
            }
        }
        return window.promisecrypt.exportKey.apply(window.promisecrypt.exportKey, args);
    },
    importKey: function() {
        var args = Array.prototype.slice.call(arguments, [0, 4]);
        var algorithm = args[2];
        if (algorithm) {
            switch (algorithm["name"]) {
            case "AES-MAC":
                return JOSE.CBC_MAC.importKey.apply(JOSE.CBC_MAC.importKey, args);

            default:
                break;
            }
        }
        return window.promisecrypt.importKey.apply(window.promisecrypt.importKey, args);
    },
    decrypt: function() {
        var args = Array.prototype.slice.call(arguments, [0, 3]);
        var algorithm = args[0];
        if (algorithm) {
            switch (algorithm["name"]) {
            case "AES-MAC":
                return JOSE.CBC_MAC.decrypt.apply(JOSE.CBC_MAC.decrypt, args);

            default:
                break;
            }
        }
        return window.promisecrypt.decrypt.apply(window.promisecrypt.decrypt, args);
    },
    encrypt: function() {
        var args = Array.prototype.slice.call(arguments, [0, 3]);
        var algorithm = args[0];
        if (algorithm) {
            switch (algorithm["name"]) {
            case "AES-MAC":
                return JOSE.CBC_MAC.encrypt.apply(JOSE.CBC_MAC.encrypt, args);

            default:
                break;
            }
        }
        return window.promisecrypt.encrypt.apply(window.promisecrypt.encrypt, args);
    },
    wrapKey: function(format, key, wrappingKey, wrapAlgorithm) {
        var d = Q.defer();

        JOSE.promisecrypt.exportKey(format, key).then(
            function (keyData) {
                JOSE.promisecrypt.encrypt(wrapAlgorithm, wrappingKey, keyData).then(
                    function (data) {
                        d.fulfill(data);
                        return data;
                    },
                    function () { d.reject(); }
                )
            },
            function() { d.reject(); }
        )

        return d.promise;
    },
    unwrapKey: function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        if (extractable == null) extractable = false;
        if (keyUsages == null) keyUsages = [];


        var d = Q.defer();
        
        JOSE.promisecrypt.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey).then(
            function (keyData) {
                JOSE.promisecrypt.importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages).then(
                    function (key) { 
                        d.fulfill(key);
                        return key;
                    },
                    function () { d.reject(); }
                );
            },
            function () { d.reject(); }
        )

        return d.promise;
    }
}
