(function() {
    function MakePromise(op, isCryptoOperation) {
        if (op == null) {
            return;
        }
        var d = Q.defer();
        var opSave = op;
        op.oncomplete = function(e) {
            d.resolve(e.target.result);
        };
        op.onerror = function(e) {
            d.reject();
        };
        if (isCryptoOperation) {
            d.promise.process = function(buffer) {
                var op2 = opSave.process(buffer);
                if (op2 == null) op2 = opSave;
                return MakePromise(op2, true);
            }
            d.promise.finish = function() {
                var op2 = opSave.finish();
                if (op2 == null) op2 = opSave;
                return MakePromise(op2, true);
            }
            d.promise.abort = function() {
                var op2 = opSave.abort();
                if (op2 == null) op2 = opSave;
                return MakePromise(op2, true);
            }
            d.promise.algorithm = function() { return opSave.algorithm; }
        }
        return d.promise;
    }

    function co2p(f, n, isCryptoOperation) {
        return function() {
            var args = Array.prototype.slice.call(arguments, [0,n]);
            var op = f.apply(window.polycrypt, args);

            return MakePromise(op, isCryptoOperation);
        };
    }
    
    window.promisecrypt = {
        // CryptoOperation
        digest:  co2p( window.polycrypt.digest, 2, true ),
        encrypt: co2p( window.polycrypt.encrypt, 3, true ),
        decrypt: co2p( window.polycrypt.decrypt, 3, true ),
        sign: co2p( window.polycrypt.sign, 3, true ),
        verify: co2p( window.polycrypt.verify, 4, true ),
    
        // KeyOperation
        importKey: co2p( window.polycrypt.importKey, 4, false ),
        exportKey: co2p( window.polycrypt.exportKey, 4, false ),
        generateKey: co2p( window.polycrypt.generateKey, 3, false ),
        wrapKey: co2p( window.polycrypt.wrapKey, 4, false),
        unwrapKey: co2p( window.polycrypt.unwrapKey, 7, false),
    }
})();
