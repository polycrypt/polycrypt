var privKey, pubKey, cert;
var email = null;
var password = null;
var options = {
    encAlg: '3des'
}

var FurtherSteps = {
    begin_cert_verify:      7,
    complete_cert_verify:   8,
    fail_cert_verify:       9
};

function updateDisplay(s) {
    var gen = document.getElementById("gen");
    var sig = document.getElementById("sig");
    var ver = document.getElementById("ver");
    var done = document.getElementById("done");

    switch (s) {
        case CertFactory.steps.begin_key_generation:
            gen.className = "working";
            sig.className = "off";
            ver.className = "off";
            done.className = "hidden";
            break;
        case CertFactory.steps.complete_key_generation:
            break;
        case CertFactory.steps.begin_key_export:
            break;
        case CertFactory.steps.complete_key_export:
            gen.innerHTML += " done";
            gen.className = "on";
            break;
        case CertFactory.steps.begin_cert_sign:
            sig.className = "working";
            break;
        case CertFactory.steps.complete_cert_sign:
            sig.innerHTML += " done";
            sig.className = "on";
            break;
        case FurtherSteps.begin_cert_verify:
            ver.className = "working";
            break;
        case FurtherSteps.complete_cert_verify:
            ver.className = "on";
            ver.innerHTML += " done";
            done.className = "on";
            /* TODO: Display results */
            break;
        case FurtherSteps.fail_cert_verify:
            ver.className = "working";
            ver.innerHTML = "<b>FAILED VERIFICATION</b>";
            break;
    }
}

function verifyCert() {
    updateDisplay(FurtherSteps.begin_cert_verify);
    
    // 1. Check that it passes Forge verification
    cert.md = forge.md.sha1.create();
    var bytes = forge.asn1.toDer(forge.pki.getTBSCertificate(cert));
    cert.md.update(bytes.getBytes());
    var forgeVerified = false;
    try {
        forgeVerified = cert.verify(cert);
    } catch (ex) {
        console.log("VERIFY FAILURE :: " + ex)
        console.log(ex);
    }
    if (!forgeVerified) {
        handleVerificationFailure();
        return;
    }

    // 2. Check that it verifies under the cached publicKey object
    // Convert TBSCertificate and signature to ABV;
    var tbsc = forge.asn1.toDer(forge.pki.getTBSCertificate(cert));
    tbsc = util.hex2abv(tbsc.toHex());
    var sig = util.hex2abv(forge.util.bytesToHex(cert.signature));
    var op = window.polycrypt.verify("RSASSA-PKCS1-v1_5", pubKey, sig, tbsc);
    op.onerror = handleVerificationFailure;
    op.oncomplete = handleVerificationComplete;
}

function handleVerificationFailure(e) {
    updateDisplay(FurtherSteps.fail_cert_verify);
}

function handleVerificationComplete(e) {
    console.log(e.target.result);
    if (e.target.result == false) {
        // XXX: Sometimes e.target.result == null
        //      Is there a race condition here?
        handleVerificationFailure();
        return;
    }

    // Export the private key for display
    var op = window.polycrypt.exportKey("jwk", privKey);
    op.onerror = handleVerificationFailure;
    op.oncomplete = displayResults;
}

function displayResults(e) {
    // Convert the private key to a forge key
    var jwk = e.target.result;
    var privHex = {};
    for (ix in jwk) {
        privHex[ix] = util.abv2hex(util.b64decode(jwk[ix]));
    }
    var privRSA = forge.pki.rsa.setPrivateKey(
        new BigInteger(privHex.n, 16),
        new BigInteger(privHex.e, 16),
        new BigInteger(privHex.d, 16),
        new BigInteger(privHex.p, 16),
        new BigInteger(privHex.q, 16),
        new BigInteger(privHex.dmp, 16),
        new BigInteger(privHex.dmq, 16),
        new BigInteger(privHex.coeff, 16)
    );

    // Serialize the private key
    var privPEM = forge.pki.privateKeyToPem(privRSA);
    var privP12 = forge.asn1.toDer(
        forge.pkcs12.toPkcs12Asn1(privRSA, cert, password, options)
    ).getBytes();
    window.p12 = {
        privRSA: privRSA,
        cert: cert,
        password: password,
        options: options,
        p12: privP12
    };

    // Serialize the cert
    var certDER = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    var certPEM = forge.pki.certificateToPem(cert);

    // Publish as data URIs
    function dataURI(type, str) {
        return "data:"+ type + ";base64," + forge.util.encode64(str);
    }
    document.getElementById("privPEM").href = dataURI("application/x-pem-file", privPEM);
    document.getElementById("privP12").href = dataURI("application/x-pkcs12", privP12);
    document.getElementById("certPEM").href = dataURI("application/x-pem-file", certPEM);
    document.getElementById("certDER").href = dataURI("application/pkix-cert", certDER);
    
    updateDisplay(FurtherSteps.complete_cert_verify);
}

function togglePassword() {
    var p = document.getElementById("password");
    p.type = (p.type == "password")? "text" : "password";
}

function go() {
    // Cache parameters
    var e = document.getElementById("email");
    var p = document.getElementById("password");
    email = e.value;
    password = p.value;
    e.disabled = true;
    p.disabled = true;
    e.className = "disabled";
    p.className = "disabled";

    // Validate input 

    // Pre-compute some values
    var notBefore = new Date();
    notBefore.setTime(notBefore.getTime() - 60*60*1000);
    var notAfter = new Date(notBefore);
    notAfter.setFullYear(notBefore.getFullYear() + 1);
    var name = [
        { name: 'countryName', value: 'US' },
        { name: 'commonName', value: email },
        { name: 'emailAddress', value: email }
    ];

    var opt = {
        serialNumber: '01',
        notBefore: notBefore,
        notAfter: notAfter,
        issuer: name,
        subject: name,
        extensions: [
            {
                name: 'basicConstraints',
                cA: true
            },
            {
                name: 'keyUsage',
                keyCertSign: true,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true
            },
            {
                name: 'subjectAltName',
                altNames: [
                    { type: 1, value: email }
                ]
            }
        ]
    }

    scb = function(privKey, pubKey, cert) {
        window.privKey = privKey;
        window.pubKey = pubKey;
        window.cert = cert;
        verifyCert()
    };

    ecb = function(e) {
        console.log("ERROR :: " + e.target.result);
    };

    pcb = function(s) {
        updateDisplay(s);
    };

    CertFactory.create({
        success: scb,
        error: ecb,
        progress: pcb
    }, opt);
}

