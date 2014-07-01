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

Impl.extend({

    export: function worker_export(args) {
        'use strict';

        var format = args['format'] || null;
        var key = args['key'] || null;
      
        console.log(JSON.stringify(args));

        if (!key) {
            this.die('You must provide a key to export');
            return;
        }

        if (('exportable' in key)&&(key.exportable === false)) {
            this.die('Attempt to export a non-exportable key');
            return;
        }

        // Unwrap the key
        var rawKey = libpolycrypt.unwrap_key(this.apiKey, key);

        var algoName = this.algoName(key.algorithm);
        switch (algoName) {
            // Raw symmetric key
            case null:
                // XXX-SPEC: Assuming that this is symmetric?
            case "AES-CTR":
            case "AES-CBC":
            case "AES-GCM":
            case "HMAC":
                if (format === 'raw') {
                    this.complete(rawKey.key);
                } else {
                    this.die('Only raw key supported for algorithm ' + algoName);
                    return;
                }
                
                break;

            case "RSASSA-PKCS1-v1_5":
            case "RSAES-PKCS1-v1_5":
                if((format !== 'jwk') && (format !== 'spki') && (format !== 'pkcs8'))
                {
                    this.die('Only jwk, spki and pkcs8 key supported for algorithm ' + algoName);
                    return;
                }

                if(format === 'jwk')
                {
                    var jwk = {};
                    for(var ix in rawKey.key)
                    {
                        jwk[ix] = util.b64encode(util.hex2abv(rawKey.key[ix]));
                    }

                    this.complete(jwk);
                }

                if(format === 'spki')
                {
                    // #region Major return variable 
                    var asn1 =
                    {
                        name: 'SubjectPublicKeyInfo',
                        tagClass: forge.asn1.Class.UNIVERSAL,
                        type: forge.asn1.Type.SEQUENCE,
                        composed: true,
                        constructed: true,
                        value: new Array()
                    };
                    // #endregion 

                    // #region Push information about "AlgorithmIdentifier" 
                    asn1.value.push({
                        name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
                        tagClass: forge.asn1.Class.UNIVERSAL,
                        type: forge.asn1.Type.SEQUENCE,
                        composed: true,
                        constructed: true,
                        value: [{
                            name: 'AlgorithmIdentifier.algorithm',
                            tagClass: forge.asn1.Class.UNIVERSAL,
                            type: forge.asn1.Type.OID,
                            composed: false,
                            constructed: false,
                            value: (forge.asn1.oidToDer("1.2.840.113549.1.1.1")).bytes()
                        },
                        {
                            name: 'AlgorithmIdentifier.parameters',
                            tagClass: forge.asn1.Class.UNIVERSAL,
                            type: forge.asn1.Type.NULL,
                            composed: false,
                            constructed: false,
                            value: ""
                        }
                        ]
                    });
                    // #endregion 

                    // #region Create DER encoding for public key 
                    var rsaKey_asn1 =
                        {
                            // subjectPublicKey
                            name: 'SubjectPublicKeyInfo.subjectPublicKey',
                            tagClass: forge.asn1.Class.UNIVERSAL,
                            type: forge.asn1.Type.BITSTRING,
                            constructed: false,
                            composed: true,
                            value: [{
                                // RSAPublicKey
                                name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
                                tagClass: forge.asn1.Class.UNIVERSAL,
                                type: forge.asn1.Type.SEQUENCE,
                                constructed: true,
                                composed: true,
                                value: [{
                                    // modulus (n)
                                    name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey.modulus',
                                    tagClass: forge.asn1.Class.UNIVERSAL,
                                    type: forge.asn1.Type.INTEGER,
                                    constructed: false,
                                    composed: false,
                                    value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.n))
                                }, {
                                    // publicExponent (e)
                                    name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey.exponent',
                                    tagClass: forge.asn1.Class.UNIVERSAL,
                                    type: forge.asn1.Type.INTEGER,
                                    constructed: false,
                                    composed: false,
                                    value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.e))
                                }]
                            }]
                        };
                    // #endregion 

                    // #region Push information about "subjectPublicKey" 
                    asn1.value.push(rsaKey_asn1);
                    // #endregion 

                    // #region Encode ASN.1 structure and return
                    var der_bytes = (forge.asn1.toDer(asn1)).bytes();
                    this.complete(util.u82abv(der_bytes));
                    // #endregion 
                }

                if(format === 'pkcs8')
                {
                    var rsa_asn1 =
                                                {
                                                    // RSAPrivateKey
                                                    name: 'RSAPrivateKey',
                                                    tagClass: forge.asn1.Class.UNIVERSAL,
                                                    type: forge.asn1.Type.SEQUENCE,
                                                    constructed: true,
                                                    composed: true,
                                                    value: [
                                                            {
                                                                // Version (INTEGER)
                                                                name: 'RSAPrivateKey.version',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.call(null, 0)
                                                            },
                                                            {
                                                                // modulus (n)
                                                                name: 'RSAPrivateKey.modulus',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.n))
                                                            },
                                                            {
                                                                // publicExponent (e)
                                                                name: 'RSAPrivateKey.publicExponent',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.e))
                                                            },
                                                            {
                                                                // privateExponent (d)
                                                                name: 'RSAPrivateKey.privateExponent',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.d))
                                                            },
                                                            {
                                                                // prime1 (p)
                                                                name: 'RSAPrivateKey.prime1',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.p))
                                                            },
                                                            {
                                                                // prime2 (q)
                                                                name: 'RSAPrivateKey.prime2',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.q))
                                                            },
                                                            {
                                                                // exponent1 (d mod (p-1))
                                                                name: 'RSAPrivateKey.exponent1',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.dmp1))
                                                            },
                                                            {
                                                                // exponent2 (d mod (q-1))
                                                                name: 'RSAPrivateKey.exponent2',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.dmq1))
                                                            },
                                                            {
                                                                // coefficient ((inverse of q) mod p)
                                                                name: 'RSAPrivateKey.coefficient',
                                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                                type: forge.asn1.Type.INTEGER,
                                                                constructed: false,
                                                                value: String.fromCharCode.apply(null, util.hex2abv(rawKey.key.coeff))
                                                            }
                                                    ]
                                                };

                    var der_bytes_rsa = (forge.asn1.toDer(rsa_asn1)).bytes();

                    // #region Create private key ASN.1 structure 
                    var privateKey_asn1 =
                        {
                        // PrivateKeyInfo
                        name: 'PrivateKeyInfo',
                        tagClass: forge.asn1.Class.UNIVERSAL,
                        type: forge.asn1.Type.SEQUENCE,
                        constructed: true,
                        composed: true,
                        value: [
                                {
                                    // Version (INTEGER)
                                    name: 'PrivateKeyInfo.version',
                                    tagClass: forge.asn1.Class.UNIVERSAL,
                                    type: forge.asn1.Type.INTEGER,
                                    constructed: false,
                                    value:String.fromCharCode.call(null,0)
                                },
                                {
                                    // privateKeyAlgorithm
                                    name: 'PrivateKeyInfo.privateKeyAlgorithm',
                                    tagClass: forge.asn1.Class.UNIVERSAL,
                                    type: forge.asn1.Type.SEQUENCE,
                                    constructed: true,
                                    composed: true,
                                    value: [
                                            {
                                            name: 'AlgorithmIdentifier.algorithm',
                                            tagClass: forge.asn1.Class.UNIVERSAL,
                                            type: forge.asn1.Type.OID,
                                            constructed: false,
                                            value: (forge.asn1.oidToDer('1.2.840.113549.1.1.1')).bytes()
                                            },
                                            {
                                                name: 'AlgorithmIdentifier.parameters',
                                                tagClass: forge.asn1.Class.UNIVERSAL,
                                                type: forge.asn1.Type.NULL,
                                                composed: false,
                                                constructed: false,
                                                value: ""
                                            }
                                           ]
                                },
                                {
                                    // PrivateKey
                                    name: 'PrivateKeyInfo',
                                    tagClass: forge.asn1.Class.UNIVERSAL,
                                    type: forge.asn1.Type.OCTETSTRING,
                                    constructed: false,
                                    composed: false,
                                    value: [der_bytes_rsa]
                                }
                               ]
                    };
                    // #endregion 

                    // #region Encode to der 
                    var der_bytes = (forge.asn1.toDer(privateKey_asn1)).bytes();
                    this.complete(util.u82abv(der_bytes));
                    // #endregion 
                }

                break;

            default:
                this.die("Unsupported algorithm: " + algoName);
                return;
        }
    },

});
