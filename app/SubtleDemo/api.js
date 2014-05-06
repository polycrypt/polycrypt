/* ====================== HELPER API ====================== */

/*
 *  Who likes typing "document.getElementById(id)" all the time?  Lets make it easier
 *  @param id the id of the element to get
 *  @return the object representing HTML element with the given id
 */
var GET = function(id) {
    return document.getElementById(id);
}

/* ====================== CHAT APPLICATION API ====================== */

/*
 *  Put text into a specific document element 
 *  @param Operation the completed Encrypt/Decrypt operation with our ciphertext/plaintext
 *  @param where the id of the element to change the value of
 */
var putText = function(Operation, where) {
    var loc = GET(where);
    loc.value = Operation.result;
}

/*
 *  Process finishing encrypting a message by displaying it to the user, then decrypting the message
 *  @param EncryptedResult the result of encrypting the message
 */
var handleChat = function(EncryptedResult, where) {
    putText(EncryptedResult, "ciphertext" + where.from);
    putText(EncryptedResult, "rCiphertext" + where.to);

    DecryptDataWrapper(EncryptedResult, putText, "rPlaintext" + where.to);
}

/* 
 *  Send an encrypted chat message to the other peer
 *  @param message a String message to send
 *  @param source which peer is sending
 *  @param destination which peer to send it to
 */ 
var SendChatMessage = function(source, destination) {
   EncryptDataWrapper(GET("plaintext" + source).value, handleChat, {from:source, to:destination});
}

/* =============================================================
 * =============================================================
 * =============================================================
 * =============================================================
 * ================= SubtleCrypto Wrapper API ==================
 * =============================================================
 * =============================================================
 * =============================================================
 * ============================================================= */

/* ====================== DO SOME CLEANUP ====================== */

/*
 *  Delete our old test key (if it exists)
 *  Set static key data for ease of use
 *  Set a static key for easy of use
 */
window.crypto.token.deleteSymKey("Hello-Chat Test Key");
var data = util.hex2abv("11111111111111111111111111111111");
var KEY = window.crypto.subtle.importKey(["secret"], ["raw"], data, "aes-cbc", "Hello-Chat Test Key", false, 3);

/* ====================== HELPER API ====================== */

/*
 *  Handles an entire Encryption Operation using 128-bit AES-CTR
 *  
 *  As long as you are only using EncryptDataWrapper and 
 *  DecryptDataWrapper, you do not need to be concerned about the
 *  EncryptionResult object, just know that EncryptionResult.result will
 *  be your ciphertext.
 *
 *  @param message a String to encrypt
 *  @param resultCallback callback function 
 *  @param callbackParams parameters for the callback function
 *
 *  The callback function will be called in the following manner:
 *
 *  if (resultCallback && callbackParams) {
 *      resultCallback(EncryptionResult, callbackParams);
 *  } else if (resultCallback) {
 *      resultCallback(EncryptionResult);
 *  } else {
 *      console.log("Ciphertext: " + EncryptionResult.result);
 *  }
 *
 *  where EncryptionResult = {result, params} 
 *      result is a hex-encoded String of the ciphertext
 *      params is an object containing the encryption's parameters
 */
var EncryptDataWrapper = function(message, resultCallback, callbackParams) {
    //Encrypt our message
    var EncryptOperation = encrypt(message, KEY);

    //Set up event handlers
    EncryptOperation.op.onerror = function() {
        console.log("Encryption error: " + this.error.name);
        console.log("Plaintext: " + message);
        console.log("Initialization Vector: " + EncryptOperation.iv);
    }

    //Call our callback function with optional parameters
    EncryptOperation.op.onsuccess = function() {
        var EncryptionResult = {result: this.result, params: EncryptOperation.iv};
        
        if (resultCallback && callbackParams) {
            resultCallback(EncryptionResult, callbackParams);
        } else if (resultCallback) {
            resultCallback(EncryptionResult);
        } else {
            //No callback function, print to standard out
            console.log("Ciphertext: " + EncryptionResult.result);
        }
    }
}

/*
 *  Handles an entire Decryption Operation using 128-bit AES-CTR
 *
 *  As long as you are only using EncryptDataWrapper and 
 *  DecryptDataWrapper, you do not need to be concerned about the
 *  DecryptionResult object, just know that DecryptionResult.result will
 *  be your plaintext.
 *
 *  @param ciphertext a hex-encoded String ciphertext
 *  @param params any parameters needed (for example, hex-encoded string of an IV)
 *  @param resultCallback callback function
 *  @param callbackParams parameters for the callback function
 *
 *  if (resultCallback && callbackParams) {
 *      resultCallback(DecryptionResult, callbackParams);
 *  } else if (resultCallback) {
 *      resultCallback(EncryptionResult);
 *  } else {
 *      console.log("Plaintext: " + DecryptionResult.result);
 *  }
 *
 *  where DecryptionResult = {result, params} 
 *      result is a String encoded plaintext
 *      params is an object containing the encryption's parameters
 */ 
var DecryptDataWrapper = function(EncryptionResult, resultCallback, callbackParams) {
    //Rename our parameters for decryption
    var DecryptOperationData = {iv:EncryptionResult.params, ciphertext:EncryptionResult.result};

    //Call our lower-level API to perform the operation
    var DecryptOperation = decrypt(DecryptOperationData, KEY);

    //Set up event handlers for our decrypt operation
    DecryptOperation.onerror = function() {
        console.log("Decryption error: " + this.error.name);
        console.log("Ciphertext: " + ciphertext);
        console.log("Initialization Vector: " + params);
    }

    //Call the given callback function with optional arguments
    DecryptOperation.onsuccess = function() {
        var DecryptionResult = {result: util.abv2str(util.hex2abv(this.result)), params: DecryptOperationData.iv};
        
        if (resultCallback && callbackParams) {
            resultCallback(DecryptionResult, callbackParams);
        } else if (resultCallback) {
            resultCallback(EncryptionResult);
        } else {
            //No callback function, print to standard out
            console.log("Plaintext: " + DecryptionResult.result);
        }
    }
}

/* ====================== LOW-LEVEL API ====================== */

/*
 *  Encrypt a message using the given key
 *  @param message a string message to encrypt
 *  @param key the key to encrypt the message using
 *  @return result of the encryption {iv: IV, op: encOp}
 */ 
var encrypt = function(message, key) {
    //First make sure that we have all the right objects
    if (message && message.length == 0) {
        return null;
    }

    if (!key) {
        return null;
    }

    //Convert the message into an ArrayBufferView
    var pt = util.str2abv(message);

    //Generate a new pseudorandom IV using the browser's PRNG
    newIv = window.crypto.getRandomValues(new Uint8Array(16));
    var algorithm = {name:"aes-cbc", iv: newIv};

    //DOMRequest that runs the actual encryption
    var encOp = window.crypto.subtle.encrypt(algorithm, key, pt);

    return {iv: util.abv2hex(newIv), op:encOp};
}

/*
 *  Decrypt a ciphertext using the given key and IV
 *  @param encryptResult a JSON object of the form: {iv: IV, ct: ciphtertext}
 *      iv is a Hex-String representation of a pseudorandom initialization vector
 *      result is a hex-encoded String containing the ciphertext to decrypt
 *  @param key the key object
 */
var decrypt = function(encryptResult, key) {
    //First make sure that we have all the right objects
    if (encryptResult.ciphertext && encryptResult.ciphertext.length == 0) {
        return null;
    }

    if (encryptResult.iv && encryptResult.iv.length == 0) {
        return null;
    }

    if (!key) {
        return null;
    }   
   
    //Convert all of our data to ArrayBufferViews
    var ct = util.hex2abv(encryptResult.ciphertext);
    var IV = util.hex2abv(encryptResult.iv);
    var algorithm = {name:"aes-cbc", iv:IV};

    //DOMRequest that runs the actual decryption
    var decOp = window.crypto.subtle.decrypt(algorithm, key, ct);

    return decOp;
}
