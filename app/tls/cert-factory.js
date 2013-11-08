var CertFactory = (function() {
    var cf = {};
    var privKey, pubKey, cert;
    var opt = {}
    var on = {
        success: function() {},
        error: function() {},
        progress: function() {}
    };

    cf.steps = {
        begin_key_generation:       1,
        complete_key_generation:    2,
        begin_key_export:           3,
        complete_key_export:        4,
        begin_cert_sign:            5,
        complete_cert_sign:         6
    }
    
    function step1() {
        on.progress(cf.steps.begin_key_generation);
        // Initiate key generation
        // Callback to step 2
        var op = window.polycrypt.generateKey({
            name: "RSASSA-PKCS1-v1_5",

            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01])
        });
        op.onerror = handleError;
        op.oncomplete = step2;
    };
    
    function step2(e) {
        on.progress(cf.steps.complete_key_generation);
        window.keyPair = e.target.result;
        // Cache the keys for later use
        privKey = e.target.result.privateKey;
        pubKey = e.target.result.publicKey;
        // Export public key
        // Callback to step 3
        on.progress(cf.steps.begin_key_export);
        var op = window.polycrypt.exportKey("jwk", pubKey);
        op.onerror = handleError;
        op.oncomplete = step3;
    };
    
    function step3(e) {
        on.progress(cf.steps.complete_key_export);
        on.progress(cf.steps.begin_cert_sign);
        var jwk = e.target.result;
        
        // Construct certificate based on opt 
        cert = forge.pki.createCertificate();
        cert.serialNumber = opt.serialNumber;
        cert.validity.notBefore = opt.notBefore;
        cert.validity.notAfter = opt.notAfter;
        cert.setSubject(opt.subject);
        cert.setIssuer(opt.issuer);
        cert.setExtensions(opt.extensions);
        // Set public key from JWK
        cert.publicKey = forge.pki.rsa.setPublicKey(
            new BigInteger(util.abv2hex(util.b64decode(jwk.n)), 16),
            new BigInteger(util.abv2hex(util.b64decode(jwk.e)), 16)
        );
        // Set signature OIDs (forge does this in sign())
        cert.signatureOid = forge.pki.oids['sha1withRSAEncryption'];
        cert.siginfo.algorithmOid = forge.pki.oids['sha1withRSAEncryption'];

        // Convert TBSCertificate to ArrayBufferView
        var tbsc = forge.asn1.toDer(forge.pki.getTBSCertificate(cert));
        tbsc = util.hex2abv(tbsc.toHex());

        // Initiate signing
        // Callback to step 4
        var op = window.polycrypt.sign({
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-1"
            }, privKey, tbsc);
        op.onerror = handleError;
        op.oncomplete = step4;
    };
    
    function step4(e) {
        var sigval = e.target.result;

        // Convert signature to byte string and attach to certificate
        cert.signature = forge.util.hexToBytes(util.abv2hex(sigval));
        
        // Invoke success callback
        on.progress(cf.steps.complete_cert_sign);
        on.success(privKey, pubKey, cert);
    };
    
    function handleError(e) {
        // Invoke error callback
        on.error(e);
    };
    
    cf.create = function(callbacks, options) {
        if (options) { opt = options; }
        if (callbacks.success) { on.success = callbacks.success; }
        if (callbacks.error) { on.error = callbacks.error; }
        if (callbacks.progress) { on.progress = callbacks.progress; }
        step1();
    }

    return cf;
})();

