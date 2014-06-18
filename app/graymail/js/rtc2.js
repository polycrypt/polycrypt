/*
    We see if nfCrypto is loaded.  If so, use it when we can.
    Otherwise, we use polycrypt. Polycrypt and nfCrypto use 
    different string character encodings.  They also implement
    the WebCrypto spec slightly differently so the "choice" variable
    will allow the clients to successfully communicate.
*/
var defaultapi = window.polycrypt;
var choice = "";
var api = null;

if (window.nfCrypto == undefined) {
    api = window.polycrypt;
    choice = "polycrypt";
} else {
    api = window.nfCrypto.subtle;
    choice = "nfcrypto";
}

/* Event Driven interface to listen for updates from the server */
var signalingChannel = new Object();

/* The ICE servers we will use */
var iceServers = {
	iceServers : [ 
        {url : 'stun:stun.1.google.com:19302'}, 
        {url : 'stun:stun.services.mozilla.com'} 
    ]
};

/* Required for use with DataChannel */
var optionalRtpDataChannels = {
	optional : [ {
		RtpDataChannels : true
	} ]
}

var pc;
var channel;

var userRSAKey = null; 
var userPublicKeyJWK = null; 
var userNonceAbv = null; 
var userNonceHashed = null; 
var otherPublicKeyJWK = null;
var otherRSAPublicKey = null; 
var otherNonceEncrypted = null;
var otherNonceAbv = null;
var otherNonceHashed = null;
var password = null;
var derivedKey = null;

window.okToSend = true;
window.ice = new Array();
window.iceCandidates = new Array();
window.remoteDescriptionSet = false;

// call start(true) to initiate
function start(isInitiator) {
    pc = new RTCPeerConnection(iceServers, optionalRtpDataChannels);

	// send any ice candidates to the other peer
	pc.onicecandidate = function(evt) {
        if (evt.candidate) {
            window.ice.push(JSON.stringify({"candidate" : evt.candidate}));
            if (window.OkToSend) {
                sendNextIce();
            }
        } 
    }

	if (isInitiator) {
		// create data channel and setup chat
		channel = pc.createDataChannel("chat", {
			reliable : false
		});

        pc.createOffer(localDescCreated, logError);
		setupChat();
	} else {
		// setup chat on incoming data channel
		pc.ondatachannel = function(evt) {
			channel = evt.channel;
			setupChat();
		}
	}
}

function sendNextIce() {
    if (window.OkToSend) {
        window.OkToSend = false;
        signalingChannel.send(window.ice.pop());
    }
}

function localDescCreated(desc) {
    pc.setLocalDescription(desc, function() {
        signalingChannel.send(JSON.stringify( {
			"sdp" : pc.localDescription
		}));
	}, logError);
    window.remoteDescriptionSet = true;
    
    flushIceCandidates();
}

signalingChannel.send = function(toSend) {
	var request = new XMLHttpRequest();
	request.open("POST", "./py/update.py", true);
    request.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
	request.send("userId=" + userId + "&roomId=" + roomId + "&msg=" + encodeURIComponent(toSend));
    
    request.onload = function() {
        window.OkToSend = true;
        if (window.ice.length > 0) {
            sendNextIce();
        }
    }
}

function flushIceCandidates() {
    if (window.remoteDescriptionSet) {
        while (window.iceCandidates.length > 0) {
            pc.addIceCandidate(new RTCIceCandidate(window.iceCandidates.pop()));
        }
    }
}

signalingChannel.onMessage = function(evt) {
	if (!pc)
		start(false);

    var message = JSON.parse(evt);

	if (message.sdp) {
        pc.setRemoteDescription(new RTCSessionDescription(message.sdp),
			function() {
     		    if (pc.remoteDescription.type == "offer") {
        		    pc.createAnswer(localDescCreated, logError);
     		    }
		});
	} else {
        window.iceCandidates.push(message.candidate);
    }

    flushIceCandidates();
};

/* whether or not the webrtc connection is currently established */
var webrtc = false;

/*
 * Setup channel functionality
 */
function setupChat() {
	
	/*
	 * Stop polling when the chat is negotiated
	 * Start the Polycrypt.js handshake
	 */
	channel.onopen = function() {
		console.log("Webrtc set up!");

        window.clearInterval(timer);
		updateChat("Establishing secure connection...");
		webrtc = true;
        
        if (webrtc && accepted) {
            startRSA();
        }
	}

	/*
	 * If we can parse the msg as JSON, its a crypto message
	 * Otherwise it is a regular message so decrypt it
	 */
	channel.onmessage = function(evt) {
		var payload = evt.data;
		try {
			payload = JSON.parse(payload);
			if (payload.Crypto == true) {
                processCryptoMessage(payload);
                return;
			} else {
				//some weird message then
                return;
			}
		} catch (e) {
            console.log("\nReceived encrypted message: " + evt.data + "\n");
			decrypt(evt.data);
		}
	}
}

/*
 * Display the message to the user (and make it look nice)
 */
function displayMessage(text) {
	document.getElementById("messages").innerHTML += "<div style='padding-left:20px; text-indent:-20px;'><FONT COLOR = BLUE>" + text + "</FONT></div>";
	var temp = document.getElementById("messages");
	temp.scrollTop = temp.scrollHeight;
}

/*
 * Generate a 1024 bit RSA-Key
 */
function startRSA(callback, param) {
	generateRSAKey(1024, callback, param);
    logout();
}

var RSA_PUBLIC = "RSA-Public";
var NONCE = "Nonce";

function tryStartKeyDerivation() {
    console.log("\nChecking key derivation conditions\n");
    
    if (otherNonceAbv != null) {
        console.log("\nother nonce: " + util.abv2hex(otherNonceAbv) + "\n");
    }
    
    if (otherPublicKeyJWK != null) {
        console.log("\nother rsa:" + JSON.stringify(otherPublicKeyJWK) + "\n");
    }

    if (otherNonceAbv != null && otherPublicKeyJWK != null) {
        console.log("\nPerforming Key Derivation\n");
        deriveKey();
    } else {
        console.log("\nNot ready for key derivation... yet\n");
    }
}

/*
 * Processes a crypto message
 */
function processCryptoMessage(msg) {
	var type = msg.type;
	var payload = msg.payload;

    if (choice == "polycrypt") {
        console.log("\nReceived crypto payload: " + JSON.stringify(payload) + "\n"); 
    } else {
        console.log("\nReceived crypto payload: " + payload + "\n");
    }

    if (choice == "polycrypt") {
        var badString = payload;
        var goodString = "";

        //Polycrypt is used to dealing with strings of the for XX00YY00ZZ...00 so
        //we artificially insert those bytes here
        for (var i = 0; i < badString.length; i += 2) {
            goodString += badString.charAt(i) + badString.charAt(i + 1) + "00";
        }
    }

	/* If we received an RSA key, encrypt our nonce and send it */
	if (type == RSA_PUBLIC) {
        console.log("\nReceived an RSA key, generating a nonce and sending it\n");
        
        if (choice == "polycrypt") {
            payload = JSON.parse(util.abv2str(util.hex2abv(goodString)));
            otherPublicKeyJWK = payload;
		} else {
            otherPublicKeyJWK = util.hex2abv(payload);
        }

        generateNonce(1);
		encryptNonce();

        tryStartKeyDerivation();
	
    /* If we received a nonce, decrypt it and derive the key */
	} else if (type == NONCE) {
        console.log("\nReceived an encrypted nonce\n");
        otherNonceAbv = util.b64decode(payload);
		tryStartKeyDerivation();
	
    /* This is a garbage message */
	} else {
		return;
	}
}

/*
 * Create a JSON object of the form {Crypto: true, type: RSA_PUBLIC/NONCE, payload: msg}
 * 
 * @param type the type of Crypto message this is
 * @param msg the actual crypto information to include as a JSON object
 */
function sendCryptoMessage(type, msg) {
	msg = {
		Crypto : true,
		type : type,
		payload : msg
	}
	
    channel.send(JSON.stringify(msg));
}

/*
 * Send a message through the derived, secured channel and update the GUI
 */
function sendChatMessage(msg) {
	channel.send(msg);
	console.log("\nSent encrypted message: " + msg + "\n");
	
	//gotta make it look nice
	document.getElementById("messages").innerHTML += "<div style='padding-left:20px; text-indent:-20px;'><FONT COLOR = RED>" + name + ": " + $("#sendBox").val() + "</font></div>";
	
	var temp = document.getElementById("messages");
	temp.scrollTop = temp.scrollHeight;
	$("#sendBox").val("");
}

function logError(error) {
    console.log("\nUh oh!\n");
	console.log(error);
}

/**
 * Generate an RSA Public/Private Key Pair, send the public key as a JWK to the
 * associated client, and then wait for the other user to send their key
 * 
 * @param bits
 *            the number of bits in the key
 */
function generateRSAKey(bits) {
	/* Start generating the rsa key */
    console.log("\ngenerating your RSA key\n");
	var userPublicKeyOp = api.generateKey( {
		name : "RSAES-PKCS1-v1_5",
		params : {
			modulusLength : bits,
			publicExponent : new Uint8Array( [ 0x01, 0x00, 0x01 ])
		}
	});

	/* When key is created, export to JWK */
	userPublicKeyOp.oncomplete = function(e) {
		userRSAKey = e.target.result;

		var userPublicKeyExport = api.exportKey("jwk",
			userRSAKey.publicKey);

		userPublicKeyExport.onerror = function(e) {
			console.log("\nFailed to export the user key to JWK: " + e.target.result + "\n");
		}

		userPublicKeyExport.oncomplete = function(e) {
			if (choice == "polycrypt") {
                userPublicKeyJWK = e.target.result;
                userPublicKeyJWK.alg = "RSA1_5";
                userPublicKeyJWK.extractable = "true";
                userPublicKeyJWK.kty = "RSA";

			    /* Now send the RSA key to the othPolycrypt.  Note that we will generate a
                    UTF16 string which will appear as XX00YY00ZZ..00 so we remove the 00's
                    so it is compatible with NfCrypto
                */
			    var badString = util.abv2hex(util.str2abv(JSON.stringify(userPublicKeyJWK)));
                var goodString = "";

                for (var i = 0; i < badString.length; i+= 4) {
                    goodString += "" + badString.charAt(i) + badString.charAt(i+1);
                }

                sendCryptoMessage(RSA_PUBLIC, goodString);
		    } else {
                sendCryptoMessage(RSA_PUBLIC, util.abv2hex(e.target.result));
            }
        }
	}
}

/**
 * generate a random nonce value which will be a multiple of 32 bits
 * 
 * @param count
 *            the number of bits * 32 generateNonce(4) would produce a 32 * 4 =
 *            128 bit nonce
 */
function generateNonce(count) {
	var userNonce = new Uint32Array(count);
	window.crypto.getRandomValues(userNonce);

    var hexStr = "";
    for (var i = 0; i < userNonce.length; i++) {
        hexStr += "" + userNonce[i];
    }

    userNonceAbv = util.hex2abv(hexStr);

	var hashOp = api.digest("SHA-256", userNonceAbv);

	hashOp.onerror = function(e) {
		console.log("\nFailed to hash the user's nonce: " + e.target.result + "\n");
	}

	/* Changed to keep userNonceHashed as abv, please test! */
	hashOp.oncomplete = function(e) {
		userNonceHashed = e.target.result;
	}
}

/*
 * Encrypt the received nonce
 */
function encryptNonce() {
    console.log("\nEncrypting our nonce with the other public key\n");
	var importOp = api.importKey("jwk", otherPublicKeyJWK,
			"RSAES-PKCS1-v1_5");

	importOp.onerror = function(e) {
		console.log("\nFailed to extract the other RSA Key: " + e.target.result + "\n");
	}

	importOp.oncomplete = function(e) {
		otherRSAPublicKey = e.target.result;

		/* Encrypt the user's hashed nonce with the other user's public key */
		var encryptOp = api.encrypt("RSAES-PKCS1-v1_5",
				otherRSAPublicKey, userNonceAbv);

		encryptOp.onerror = function(e) {
			console.log("\nError encrypting your nonce: " + e.target.result + "\n");
		}

		encryptOp.oncomplete = function(e) {
			var encryptedData = e.target.result;
            sendCryptoMessage(NONCE, util.b64encode(encryptedData));
		}
	}
}

/**
 * Determines if two hashed nonces are identical
 * Assumes the two nonces (in array format) are of equal length
 *
 * @param first the first nonce
 * @param second the second nonce
 *
 * @return true if equal, falst otherwise
 */
function equal(first, second) {
    //Assumes each array is of equal length
    for (var i = 0; i < first.length; i++) {
        if (first[i] !== second[i]) {
            return false;
        }
    }

    return true;
}

/*
 * Abort the chat session, possible loss of security
 */
function selfDestruct() {
    updateChat("WARNING! THIS IS AN INSECURE SESSION, EXIT IMMEDIATELY!");
    otherNonceHashed = null;
    userNonceHashed = null;
    password = null;
    encrypt = null;
    decrypt = null;
    sendChatMessage = null;
    channel = null;
}

/*
 * Perform the key derivation procedure:
 * Key K = PBKDF2(password, H(N_A) ^ H(N_B), 2048)
 */
function deriveKey() {
	var decryptNonceOp = api.decrypt("RSAES-PKCS1-v1_5",
		userRSAKey.privateKey, otherNonceAbv);

	decryptNonceOp.onerror = function(e) {
		console.log("\nError decrypting other nonce: " + e.target.result + "\n");
	}

	decryptNonceOp.oncomplete = function(e) {
		/* Hash the other nonce using the other user's public key */
		var hashOtherNonceOp = api.digest("SHA-256", e.target.result);

		hashOtherNonceOp.onerror = function(e) {
			console.log("\nError hashing other nonce: " + e.target.result + "\n");
		}

		hashOtherNonceOp.oncomplete = function(e) {
            otherNonceHashed = e.target.result;

        if (equal(otherNonceHashed, userNonceHashed)) {
            selfDestruct();
            return;
        }

		/*
		 * Get the shared password from the user. If none exists, use the
		 * word "password"
		 */
		if (!password) {
            //No password entered, use default
			password = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
		} else {
            //Password entered, convert to abv
            password = util.hex2abv(password);
        }

		/* Generate the salt which is: salt = H(N_user) XOR H(N_other) */
		var generatedSalt = xor(otherNonceHashed, userNonceHashed);

		/*
		 * Import the shared secret (password) as a RAW symmetric key for
		 * use with PBKDF2
		 */
		var importPasswordOp = defaultapi.importKey("raw", password);

		importPasswordOp.onerror = function(e) {
			console.log("\nError importing password: " + e.target.result + "\n");
		}

		importPasswordOp.oncomplete = function(e) {
			var key = e.target.result;

			/* Derive a shared key using PBKDF2 and SHA-1 */
			var deriveKeyOp = defaultapi.deriveKey({
				name: "PBKDF2",

				salt: generatedSalt,
				iterations: 2048,
				prf: "SHA-1"
				}, key, {
					name : "AES-GCM",

					length : 128
				}, true, [ "encrypt", "decrypt" ]);

				deriveKeyOp.onerror = function(e) {
					console.log("\nError unable to derive key: " + e.target.result + "\n");
				}

				deriveKeyOp.oncomplete = function(e) {
					derivedKey = e.target.result;
					enableChat();
				}
			}
		}
	}
}

/*
 * Computes the XOR of two byte arrays Assumes the two byte arrays have the same
 * length
 *
 * @param first the first array
 * @param second the second array
 */
var xor = function(first, second) {
	var len = first.length;
	var result = new Uint8Array(len);

	for (var i = 0; i < len; i++) {
		result[i] = first[i] ^ second[i];
	}

	return result;
}

/*
 *  Encrypt the message to be sent and send it
 *  Encrypted form: IV:Encrypted Data:Additional Data
 *
 *  @param text the text to encrypt
 */
var encrypt = function(text) {
    var myIv = new Uint8Array(16);
    window.crypto.getRandomValues(myIv);

    text = name + ": " + text + "<br>";
    
    var data = util.str2abv(text);

    var additional = new Uint8Array(16);
    window.crypto.getRandomValues(additional);

    var encryptOp = defaultapi.encrypt({
        name: "AES-GCM",

        iv: myIv,
        additionalData: additional,
        tagLength: 128
    }, derivedKey, data);
            
    encryptOp.onerror = function(e) {
        console.log("\nError failed to encrypt plaintext: " + e.target.result + "\n");
    }

    encryptOp.oncomplete = function(e) {
        var all = util.abv2hex(myIv) + ":" + util.abv2hex(e.target.result) + ":" + util.abv2hex(additional);
        sendChatMessage(all);
    }
}

/*
 * Decrypt the received message and display it to the screen
 * @param text the text to decrypt
 */
var decrypt = function(text) {
    var all = text;
    
    /*
     * vals[0] = iv
     * vals[1] = output of block cipher
     * vals[2] = additionalData
     */
    var vals = all.split(":");

    var decryptOp = defaultapi.decrypt({
        name: "AES-GCM",

        iv: util.hex2abv(vals[0]),
        additionalData: util.hex2abv(vals[2]),
        tagLength: 128
    }, derivedKey, util.hex2abv(vals[1]));
    
    decryptOp.onerror = function(e) {
        console.log("\nError decrypting plaintext: " + e.target.result + "\n");
    }

    decryptOp.oncomplete = function(e) {
        displayMessage(util.abv2str(e.target.result));
    }
}
