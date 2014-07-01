/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/cipher-core-min.js');
importScripts('./lib/CryptoJS/aes-min.js');
// Crypto glue
importScripts('./libpolycrypt.js');
// Forge ASN.1 library
importScripts('./lib/Forge/util.js');
importScripts('./lib/Forge/oids.js');
importScripts('./lib/Forge/asn1.js');
importScripts('./lib/Forge/pem.js');
importScripts('./lib/Forge/pki.js');
importScripts('./lib/Forge/jsbn.js');
importScripts('./lib/Forge/pbe.js');

Impl.extend({

    import: function worker_import(args) {
        'use strict';

        var format = args['format'] || null;
        var keyData = args['keyData'] || null;
        var algorithm = args['algorithm'] || null;
        var keyUsages = args['keyUsages'] || [];
        var extractable = args['extractable'];
        if (!args.hasOwnProperty('extractable') || 
            (typeof(args.extractable) != 'boolean')) {
            extractable = false;
        }
        
        if((format !== 'raw') && (format !== 'jwk') && (format !== 'spki'))
        {
            this.die('Only raw key and jwk and spki import supported');
            return;
        }

        var type;
        var algoName = this.algoName(algorithm);
        switch (algoName) {
            // Raw symmetric key
            case null:
                // XXX-SPEC: Assuming that this is symmetric?
            case "AES-CTR":
            case "AES-CBC":
            case "AES-GCM":
            case "HMAC":
                if (format !== 'raw') {
                    this.die('Only raw key supported for algorithm ' + algoName);
                    return;
                }
                type = "secret";
                break;

            case "RSASSA-PKCS1-v1_5":
            case "RSAES-PKCS1-v1_5":
                if ((format !== 'jwk') &&
                    (format !== 'spki')){
                    this.die('Only jwk and spki key supported for algorithm ' + algoName + ' but now we have ' + format);
                    return;
                }

                if(format === 'spki')
                {
                    // #region Converting to string 
                    var r_data = String.fromCharCode.apply(null, new Uint8Array(keyData));
                    // #endregion 

                    // #region Decode DER to ASN.1 
                    var in_asn1 = forge.asn1.fromDer(r_data, false);
                    // #endregion 

                    // #region Parse ASN.1 data 
                    var capture = {};
                    var verified = forge.asn1.validate(in_asn1,
                                                      {
                                                          name: 'SubjectPublicKeyInfo',
                                                          tagClass: forge.asn1.Class.UNIVERSAL,
                                                          type: forge.asn1.Type.SEQUENCE,
                                                          constructed: true,
                                                          value: [{
                                                              name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
                                                              tagClass: forge.asn1.Class.UNIVERSAL,
                                                              type: forge.asn1.Type.SEQUENCE,
                                                              constructed: true,
                                                              value: [{
                                                                  name: 'AlgorithmIdentifier.algorithm',
                                                                  tagClass: forge.asn1.Class.UNIVERSAL,
                                                                  type: forge.asn1.Type.OID,
                                                                  constructed: false
                                                              }]
                                                          }, {
                                                              // subjectPublicKey
                                                              name: 'SubjectPublicKeyInfo.subjectPublicKey',
                                                              tagClass: forge.asn1.Class.UNIVERSAL,
                                                              type: forge.asn1.Type.BITSTRING,
                                                              constructed: false,
                                                              value: [{
                                                                  // RSAPublicKey
                                                                  name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
                                                                  tagClass: forge.asn1.Class.UNIVERSAL,
                                                                  type: forge.asn1.Type.SEQUENCE,
                                                                  constructed: true,
                                                                  optional: true,
                                                                  value: [{
                                                                            // modulus (n)
                                                                            name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey.modulus',
                                                                            tagClass: forge.asn1.Class.UNIVERSAL,
                                                                              type: forge.asn1.Type.INTEGER,
                                                                              constructed: false,
                                                                              capture: 'rsaPublicKeyModulus'
                                                                          }, {
                                                                              // publicExponent (e)
                                                                              name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey.exponent',
                                                                              tagClass: forge.asn1.Class.UNIVERSAL,
                                                                              type: forge.asn1.Type.INTEGER,
                                                                              constructed: false,
                                                                              capture: 'rsaPublicKeyExponent'
                                                                          }]
                                                      }]
                                                          }]
                                                      },
                                                      capture
                                                    );
                    if(!verified)
                        this.die("Wrong SPKI structure");
                    // #endregion 

                    // #region Init "keyData" with new values 
                    keyData = {};
                    keyData.n = util.b64encode(util.u82abv(capture.rsaPublicKeyModulus));
                    keyData.e = util.b64encode(util.u82abv(capture.rsaPublicKeyExponent));
                    // #endregion 
                }

                if((typeof (keyData) !== 'object') ||
                    (!keyData.hasOwnProperty('n')) ||
                    (!keyData.hasOwnProperty('e')))
                {
                    this.die('Malformed key data');
                    return;
                }
                var rsa = {
                    n: util.abv2hex(util.b64decode(keyData['n'])),
                    e: util.abv2hex(util.b64decode(keyData['e'])),
                };
                if(keyData.hasOwnProperty('d'))
                {
                    rsa.d = util.abv2hex(util.b64decode(keyData['d']));
                }
                keyData = rsa;
                type = (keyData.hasOwnProperty('d')) ? 'private' : 'public';

                break;

            default:
                this.die("Unsupported algorithm: " + algoName);
                return;
        }
       
        // XXX-SPEC: The spec is inconsistent between keyUsage[s]
        // XXX-SPEC: Should the policy fields be optional? (extractable / keyUsage / algorithm)
        var key = { 
            type: type, 
            key: keyData,
            algorithm: algorithm,
            extractable: extractable,
            keyUsage: keyUsages,
        };
        key = libpolycrypt.wrap_key(this.apiKey, key);
        this.complete(key);
    },

});
