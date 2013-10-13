# A rough guide to PolyCrypt

**NOTE:  this file is old.  We plan to update it, soon.**

PolyCrypt divides its functionality between two origins in order to emulate the separation between content and browser provided by the real WebCrypto API.  This document walks through how the various pieces fit together.  

The WebCrypto API is an evolving document right now.  We have tried to implement [the latest draft][WebCrypto-latest] 

[Last updated: Commit 08019b1, 29 Dec 2012]

The overall goal of PolyCrypt is to support the WebCrypto API's style of 'operations'.  Each operation provides a set of methods that initiate crypto processing, and a set of events that fire when results are ready.  For example:

    var op = window.crypto.generateKey("AES-GCM");
    op.oncomplete = function(e) {
       self.test( 0.1, 
           (e.target.result.buffer instanceof ArrayBuffer)
           && (e.target.result.byteLength in { 16: true, 24: true, 32: true})
       );
    }

Let's walk through the processes by which this overall goal is accomplished.  There are the following general phases:

1. Page load, in which the connection to the PolyCrypt origin is established
2. Object creation, in which an operation is begun
3. Method invocation, in which an app causes processing to occur
4. Event subscription, in which an app registers to receive results
5. Event propagation, in which results are delivered to the app

## Page Load

To use polycrypt, the application page loads `src/polycrypt.js`.  This file adds an event listener, `polycrypt_load()`, that does the following:

* Loads the PolyCrypt back end in an iframe
* Imports some auxiliary scripts
* Adds WebCrypto methods to `window.crypto`

The actual implementations of crypto processing done by PolyCrypt live in a separate origin from the application (notionally `http://polycrypt.net:80`).  So we need a channel to talk to these functions.  We do this by loading an invisible iframe containing the "back end" page, so that we can do postMessage back and forth to that page.

The auxiliary scripts that are loaded define (1) a convenient logging framework, (2) a standard PolyCrypt message format, (3) a pseudo-event object, and (4) a DelegatedEventTarget class that will become our operations.   The first three of these are not very important; the fourth is where all the action happens in subsequent steps.

Polycrypt's functionality is exposed through a set of methods on `window.crypto`, which apps will then call to generate crypto operations and key operations.  Each of these methods returns an operation object, which in this case will be an instance of DelegatedEventTarget (defined in `eventtarget.js`). 

DelegatedEventTarget objects are generic, however, so our methods will need to specialize them into KeyOperations or CryptoOperations (as defined in the API spec) by adding appropriate methods and event handlers.  Since methods are all implemented in the back end, the body of each method on an operation object will be a call to the object's internal `\_postMessage` method, which passes the method name and arguments to the back end.  (This is effectively a postMessage-based RPC.)

Later on, events will come back to this operation from the back end, to be dispatched to listeners.  DelegatedEventTarget objects implement the standard [EventTarget interface][eventtarget].  They will allow listeners to register for any type of event, and pass on any event received from the back end to listeners for its type.  To support HTML4-style event listener assignment, the WebCrypto API also defines listener attributes on operation objects, such as "oncomplete" or "onerror".  DelegatedEventTarget has a convenience function `_addCallback` that creates a JavaScript "setter" on the operation object for the given type of event.  For example, after `op._addCallback("complete")` has been called, the application can set a listener for "complete" events using the syntax `op.oncomplete = function(e) { ... }`.

Our `window.crypto` methods also perform an important bookkeeping function, assigning each operation a unique "operation id" (referred to as `opid` below and in the code).  In addition to creating the object, they may also initiate processing.  

The following example illustrates most of the above steps.  The only one it misses is to add a method for the app to call.  If it had defined a method, the body of the method would be similar to the `_postMessage` call at the end, copying parameters into a dictionary, specifying a method call, and sending a `_postMessage` call.

    // src/polycrypt.js:41
    window.crypto.generateKey = function(algorithm, extractable, keyUsages) {
        // Bookkeeping
        var opid = nextOpId++;

        // Instantiate DelegatedEventTarget
        var op = new DelegatedEventTarget('key-generate', opid, backend, backendOrigin);

        // Add HTML4-style event handlers
        op._addCallback('complete');
        op._addCallback('error');

        // Kick off processing (in this case, key generation)
        op._postMessage("generate", {
            algorithm: algorithm,
            extractable: extractable,
            keyUsages: keyUsages,
        });

        return op;
    };


Summary of control flow:

    <page parse>
    --> // Add window.crypto methods
    --> window.addEventListener("load", /* Set up back end iframe */)
    <page load>
    --> // Set up back end iframe


## Object Creation

A DelegatedEventTarget is mostly a translator.  It translates method calls into cross-origin messages, and passes events from the back end to listeners.  Thus, the primary goal of the DelegatedEventTarget constructor is to create the back end object that it will talk to, and to register for events coming back from the back end.  It asks the back end to create an object by using the built-in `_postMessage` method to send the special "init" command, with one argument, namely a string indicating the type of object to be created.

    // src/common/eventtarget.js:34
    // Ask the back end to create an implementation object
    this._postMessage('init', { type: type });
    
    // Register for events coming back
    var self = this;
    window.addEventListener('message', function(e) {
        self._handleMessage(e);
    });

The "init" method call prompts the back end to set up a new object with which the DelegatedEventTarget will interact.  These objects are instances WorkerDelegate class.  As its name implies, the primary function of a WorkerDelegate is to act on behalf of a [web worker][webworker], effectively an HTML5 thread that can be accessed using the postMessage design pattern.  The WorkerDelegate then acts as a pipe -- whenever it receives a message from the front end, it passes it to the worker, and vice versa.  

When a DelegatedEventTarget sends an "init" message to the back end, it is handled by the "handleInit" method.  All this method does is instantiate a new WorkerDelegate object.  When a WorkerDelegate object is created, it 

DelegatedEventTarget and WorkerDelegate objects communicate directly with each other using postMessage.  Each PolyCrypt postMessage includes an operation id (`opid`) field.  When a PolyCrypt message arrives at the back end or the front end, it will be ignored by all WorkerDelgates except the one with the same `opid`.  The "init" message is special, in that it will be handled by the "handleInit" function, regardless of its `opid`.  In this case, the `opid` is used not for routing, but to set the `opid` of the new WorkerDelegate.

Summary of control flow:

    var op = window.crypto.generateKey(...) [app]
    --> window.crypto.generateKey() [src/polycrypt.js:41]
    --> new DelegatedEventTarget() [src/common/eventtarget.js:5]
    --> DelegatedEventTarget._postMessage("init", { type: type }); [src/common/eventtarget.js:35]
    --> this.backend.postMessage(msg, this.origin) [src/common/eventtarget.js:105]
    --> handleInit(e) [src/back/back.js:17]
    --> new WorkerDelegate() [src/back/back.js:146]
    --> new Worker() [src/back/back.js:46]

## Method Invocation

As noted above, DelegatedEventTargets implement methods by passing messages to WorkerDelegates, which then get passed on to Workers for the real work.  So the method invocation process is basically just this sequence of messages.  The message contains a `method` field that specifies the method to be invoked and an `args` field with a dictionary of arguments to the method.

The one nuance is that a WorkerDelegate can add "private fields" to a message, which will only be visible to it and the worker -- not to the front end.  These fields are added to the message as it is passed to the worker, and stripped from any messages the worker sends back.  The primary example of this is the "API key" used by the back end for key wrapping.  (The WorkerDelegate itself doesn't do any key wrapping or unwrapping, but it passes the key for key wrapping back to Workers.)

Summary of control flow:

    op.generate() [app]
    --> op._postMessage("generate", ...) [src/common/eventtarget.js:94]
    --> WorkerDelegate.handleSourceMessage(e) [src/back/back.js:69]
    --> worker.postMessage(msg) [src/back/back.js:92]
    --> // Method inside of worker to handle message

## Event Subscription

In order to receive notifications of results, an app must register an event listener with the DelegatedEventTarget representing an operation.  It can do so using the standard EventTarget interface, or using the `on*` syntax noted above.  Either way, the listener is added to an internal dictionary of listeners maintained by the DelegatedEventTarget (`this.listeners`).  Listeners are stored by event type: The keys into the listener dictionary are event types, and each entry is an array of listeners.

One special thing that DelegatedEventTarget does is that it caches events to allow deferred listener registration.  Whenever an event arrives at the DelegatedEventTarget, it is cached, one event per event type.  Then, when a listener is registered, if there is a cached event, the listener is fired immediately with the cached event.  This allows listeners to be registered after an event has arrived, avoiding certain race conditions.

Summary of control flow:

    op.addEventListener(...) [app]
    --> op.addEventListener(...) [src/common/eventtarget.js:44]
     -- this.listeners[type].push(listener);
    ** /* If a cached event exists */
    --> op._fireListener(...) [src/common/eventtarget.js:74]
    --> listener

## Event Propagation

When a worker has completed its work, it will return its results as an event to the front end.  The worker generates a PolyCrypt message containing an `event` field and a `result` field.  The `event` field contains the skeleton of the event to be passed to listeners, and the `result` field contains the results of the computation.  Once the worker has constructed the message, it sends it up to its WorkerDelegate.

The WorkerDelegate adds its `opid` to the message so that it can reach the proper DelegatedEventTarget, and strips any private fields from the message.  Then the WorkerDelegate sends a `postMessage` to the front end window with the message.

The message is ignored by everyone except the relevant DelegatedEventTarget.  That object receives the message through its `_handleMessage` method, which extracts the `event` and `result` fields from the message.  The `result` field is copied to the `result` field of the DelegatedEventTarget, and the event is passed to the `dispatchEvent` method.  That method sets the target of the event to the DelegatedEventTarget, then fires each listener in the order in which they registered.  (Event capture and bubbling are not supported.)  This way, the listener can find results under `e.target.result` (where `e` is the dispatched event).

Two types of listener are supported, objects and functions.  If the listener is an object, it must have a `handleEvent` method, as required by the EventTarget API.  If this is the case, then the `handleEvent` method is called with an event.  If the listener is a function, then it is simply invoked with the event as its only argument.  The `_fireListener` method handles this distinction.

Summary of control flow:

    // Worker completes work
    --> Impl._postEvent('complete', result) [src/back/worker-key-generate.js:76]
    --> self.postMessage(msg) [src/back/worker-key-generate.js:81]
        ----- ^^^ worker ----- vvv back end -----
    --> WorkerDelegate.handleWorkerMessage(...) [src/back/back.js:95]
    --> WorkerDelegate.source.postMessage(...) [src/back/back.js:
        ----- ^^^ back end ----- vvv front end -----
    --> DelegatedEventTarget._handleMessage(...) [src/common/eventtarget.js:108]
    --> DelegatedEventTarget.dispatchEvent(...) [src/common/eventtarget.js:63]
    --> DelegatedEventTarget._fireListener(...) [src/common/eventtarget.js:74]
    --> // The listener itself


  [WebCrypto-latest]: http://dvcs.w3.org/hg/webcrypto-api/file/60de9e02a40b/spec
  [eventtarget]: http://www.w3.org/TR/DOM-Level-2-Events/
  [webworker]: http://www.w3.org/TR/workers/
