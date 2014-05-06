(function() {
    // Promises implementation adapted from: 
    // https://gist.github.com/unscriptable/814052
    // Promises implementation adapted from: 
    // https://gist.github.com/unscriptable/814052
    function Promise () {
    	this._thens = [];
    }
    Promise.prototype = {
    	then: function (onResolve, onReject) {
            var promise = new Promise();
            var resolveWrapper, rejectWrapper;
            resolveWrapper = rejectWrapper = null;
            if (onResolve) {
                resolveWrapper = function(arg) {
                    var out = onResolve(arg);
                    if (out && out.resolve) {
                        out.then( function(x) { promise.resolve(x); } )
                    } else {
                        promise.resolve(out);
                    }
                }
            }
            rejectWrapper = function(arg) {
                if (onReject) {
                    var out = onReject(arg);
                    promise.reject(out);
                } else {
                    promise.reject(arg);
                }
            }
    		this._thens.push({ resolve: resolveWrapper, reject: rejectWrapper });
            return promise;
    	},
     
    	resolve: function (val) { this._complete('resolve', val); },
    	reject: function (ex) { this._complete('reject', ex); },
     
        _complete: function (which, arg) {
    		this.then = which === 'resolve' ?
    			function (resolve, reject) { resolve(arg); } :
    			function (resolve, reject) { reject(arg); };
    		this.resolve = this.reject = 
    			function () { throw new Error('Promise already completed.'); };
    		var aThen, i = 0;
    		while (aThen = this._thens[i++]) { aThen[which] && aThen[which](arg); }
    		delete this._thens;
    	}
    };


    // CryptoOperation-to-Promise
    function co2p(f, n) {
        return function() {
            var p = new Promise();
            var args = Array.prototype.slice.call(arguments, [0,n]);
            var op = f.apply(window.polycrypt, args);
            op.oncomplete = function(e) { p.resolve(e.target.result); };
            op.onerror = function(e) { p.reject(e); };
            return p;
        };
    }
    
    window.promisecrypt = {
        // CryptoOperation
        digest: co2p( window.polycrypt.digest, 2 ),
        encrypt: co2p( window.polycrypt.encrypt, 3 ),
        decrypt: co2p( window.polycrypt.decrypt, 3 ),
        sign: co2p( window.polycrypt.sign, 3 ),
        verify: co2p( window.polycrypt.verify, 4 ),
    
        // KeyOperation
        importKey: co2p( window.polycrypt.importKey, 4 ),
        exportKey: co2p( window.polycrypt.exportKey, 4 ),
        verify: co2p( window.polycrypt.verify, 4 ),
    }
})();
