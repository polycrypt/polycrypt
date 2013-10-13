/*global self, Uint32Array */

importScripts('../common/log4js.js');
importScripts('../common/pcmessage.js');
importScripts('../common/util.js');

var console = {
    log: function(text) {
        var msg = PCMessage.create({
            method: "log",
            local: true,
            args: { text: "WORKER :: " + text }
        });
        self.postMessage(msg);
    }
};

var Impl = {
    apiKey: null,
    alive: false,

    // Constants
    src: {
        'import':       'worker-key-import.js',
        'generate':     'worker-key-generate.js',
        'derive':       'worker-key-derive.js',
        'export':       'worker-key-export.js',
        'encrypt':      'worker-encrypt.js',
        'decrypt':      'worker-decrypt.js',
        'digest':       'worker-digest.js',
        'sign':         'worker-sign.js',
        'verify':       'worker-verify.js',
    },

    init: function worker_init(args) {
        var type = args['type'];
        if (type in this.src) {
            console.log("Creating worker from " + this.src[type]);
            importScripts(this.src[type]);
        } else {
            console.log("Unknown type " + this.src[type]);
            this.die('Unknown worker type '+type);
        }
    },

    extend: function worker_extend(obj) {
        for (var property in obj) {
            if (obj.hasOwnProperty(property)) {
                this[property] = obj[property];
            }
        }
    },

    die: function worker_die(msg) {
        this.postEvent('error', msg);
        this.alive = false;
        this.close(); 
    },

    complete: function worker_complete(result) {
        // Any other cleanup goes here
        this.postEvent('complete', result);
        this.close();
    },

    close: function worker_close() {
        console.log("Closing worker");

        // Send poison pill to WorkerDelegate, then die
        var msg = PCMessage.create({
            method: "die",
            local: true,
        });
        self.postMessage(msg);
        self.close();
    },

    algoName: function worker_algoName(algorithm) {
        var name = algorithm;
        if (name && typeof(name) == 'object') { name = name['name']; }
        return name;
    },

    postEvent: function worker_postEvent(type, result) {
        console.log("Entered workerpostEvent with type " + type);
        var msg = PCMessage.create({
            event: { type: type },
            result: result
        });
        self.postMessage(msg);
    },

    postMessage: function worker_postMessage(method, args) {
        var msg = PCMessage.create({
            method: method,
            args: args,
        });
        self.postMessage(msg);
    },
};

self.onmessage = function onmessage(e) {
    console.log("Entered worker onmessage with method " + e.data.method);
    'use strict';

    var msg = e.data;

    if (msg.hasOwnProperty('apiKey')) {
        Impl.apiKey = util.hex2abv(msg['apiKey']);
    }

    if (Impl.hasOwnProperty(msg.method)) {
        console.log("Dispatched method to Impl");
        try {
            Impl[msg.method](msg.args);
        } catch (ex) {
            Impl.die(ex.message);
        }
    } else {
        console.log("Did not dispatch method to Impl");
    }
};
