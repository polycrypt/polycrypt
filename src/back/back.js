// #include <pcmessage.js>
// #include <log4js.js>

/* WorkerDelegate class */
function WorkerDelegate(type, id, source, origin) {
    this.init(type, id, source, origin);
}

WorkerDelegate.prototype = {
    // Constants
    workerSrc: "./worker.js",

    // If you modify this, please add the corresponding getter
    privateFields: [
        'apiKey'
    ],

    // Fields
    type: null,     // Type of class
    opid: null,       // Operation ID
    source: null,   // Source window (for postMessage)
    origin: null,   // Source origin (for postMessage)
    worker: null,   // Worker that does the real work

    // Methods
    init: function WorkerDelegate_init(type, opid, source, origin) {
        log4js.trace("Entered WorkerDelegate_init");

        // Validate inputs
        this.type = type;
        this.opid = opid;
        this.source = source;
        this.origin = origin;

        // Create the worker
        this.worker = new Worker(this.workerSrc);

        // Register for messages from worker
        var self = this;
        this.worker.onmessage = function(e) {
            self.handleWorkerMessage(e);
        };

        // Register for messages from source (via window)
        window.addEventListener("message", function(e) {
            self.handleSourceMessage(e);
        });

        // Pass an init message on to the worker
        this.worker.postMessage({
            method: "init",
            args: { type: this.type, },
        });
    },
    
    get apiKey() {
        var apiKeyField = "apiKey";
        if (!(apiKeyField in window.localStorage)) {
            // 128-bit key for AES key wrap
            window.localStorage[apiKeyField] = util.abv2hex(libpolycrypt.random(16));
        }
        return window.localStorage[apiKeyField];
    },

    handleSourceMessage: function WorkerDelegate_handle(e) {
        log4js.trace("Entered WorkerDelegate_handleSourceMessage", e.data);
        // Validate message
        var msg = e.data;
        if (!PCMessage.valid(msg)) { return; }
        if (!msg.toBack) { return; }
        if (!msg.hasOwnProperty('opid') || (msg.opid !== this.opid)) { return; }
        
        // Check to see if it's for us (as opposed to worker)
        if (msg.local) {
            // TODO: Handle locally (e.g., unregister and die)
            return;
        }

        // Add any private fields to the message
        // (Just between the back end and the worker)
        for (var i=0; i<this.privateFields.length; ++i) {
            var field = this.privateFields[i];
            log4js.info("Attaching private field "+field, this[field]);
            msg[field] = this[field];
        }

        // If not, pass to worker
        log4js.trace("Passing message to worker", msg);
        this.worker.postMessage(msg);
    },

    handleWorkerMessage: function WorkerDelegate_handleWorkerMessage(e) {
        log4js.trace("Entered WorkerDelegate_handleWorkerMessage", e.data);
        // Validate message
        var msg = e.data;
        if (!msg.method && !msg.event) {
            log4js.error("invalid message from worker", msg);
        }

        // Check to see if it's for us
        if (msg.local) {
            // Handle locally
            
            // Provide a logging facility for workers
            if (msg.method === "log") {
                console.log(msg.args.text);
            }

            // Clean up when a worker is done
            if (msg.method === "die") {
                this.worker = null; // worker should GC now
                // TODO: Pass die event to front end
                // TODO: removeEventListener to clear this object for GC
            }

            return;
        }
        
        // Erase any private fields before passing back to the front
        for (var i=0; i<this.privateFields.length; ++i) {
            var field = this.privateFields[i];
            log4js.info("Removing private field "+field, this[field]);
            delete msg[field];
        }

        // If not, make sure it's a real message, then pass to front
        var pc_msg = PCMessage.create(msg);
        pc_msg.opid = this.opid;
        pc_msg.toFront = true;
        this.source.postMessage(pc_msg, this.origin);
    },

};

var worker_delegates = [];
function handleInit(e) {
    'use strict';
    log4js.trace("Entered back.js:handleInit");

    // Validate the message
    var msg = e.data;
    if (!PCMessage.valid(msg) || !msg.toBack || (msg.method !== 'init')) {
        // This is not the message you're looking for
        return;
    }
    if (!msg.hasOwnProperty('opid') || !msg.hasOwnProperty('args') || !msg.args.type) {
        log4js.error("invalid init message", msg);
        return;
    }

    // Create a worker of type args.type with ID args.id
    var worker = new WorkerDelegate(
        msg.args.type, msg.opid,
        e.source, e.origin
    );
    worker_delegates.push(worker);
}

window.addEventListener("message", handleInit, false);
//-----------------------------------------------------------------------------
window.top.postMessage('polycrypt backend is alive', '*');
