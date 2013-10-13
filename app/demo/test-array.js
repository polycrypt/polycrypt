function Test(name, test) {
    this.name = name;
    this.startTime = null;
    this.endTime = null;
    this.result = null;
    this.row = null;

    this.run = function() {
        // Note the start time
        this.startTime = new Date();
        // Run the test
        try {
            test.call(this);
        } catch (e) {
            console.log(e);
            console.log(e.stack);
            this.complete(false);
        }
    };

    this.memcmp_complete = function(x, y) {
        var passfail = util.memcmp(x, y);
        if (!passfail) {
            console.log("expected: " + util.abv2hex(x));
            console.log("     got: " + util.abv2hex(y));
        }
        this.complete(passfail);
    };

    this.complete = function(result) {
        // Note the end time
        this.endTime = new Date();
        // Set result
        this.result = result;
        // Re-draw the row
        this.draw();
        
        if (this.oncomplete) {
            this.oncomplete();
        }
    };

    this.setRow = function(id) {
        this.row = document.getElementById(id).getElementsByTagName("td");
    };

    this.draw = function() {
        if (!this.row) return;
        
        // Print the name of the test
        if (this.name) {
            this.row[0].innerHTML = this.name;
        } else {
            this.row[0] = "";
        }

        // Print the result of the test
        if (this.result == true) {
            this.row[1].className = "pass";
            this.row[1].innerHTML = "PASS";
        } else if (this.result == false) {
            this.row[1].className = "fail";
            this.row[1].innerHTML = "FAIL";
        } else {
            this.row[1].innerHTML = "";
        }

        // Print the elapsed time, if known
        if (this.startTime &&  this.endTime) {
            this.row[2].innerHTML = (this.endTime - this.startTime) + " ms";
        } else {
            this.row[2].innerHTML = "";
        }
    };
}

var TestArray = {
    tests: [],
    table: null,
    passSpan: null,
    failSpan: null,
    pendingSpan: null,
    pass: 0,
    fail: 0,
    pending: 0,
    currTest: 0,

    addTest: function(name, testFn) {
        // Give it a reference to the array
        var test = new Test(name, testFn);
        test.ta = this;
        // Add test to tests
        this.tests.push(test);
    },

    updateSummary: function() {
        this.pass = this.fail = this.pending = 0;
        for (var i=0; i<this.tests.length; ++i) {
            if (this.tests[i].result == true)  this.pass++;
            if (this.tests[i].result == false) this.fail++;
            if (this.tests[i].result == null)  this.pending++;
        }
        this.passSpan.innerHTML = this.pass;
        this.failSpan.innerHTML = this.fail;
        this.pendingSpan.innerHTML = this.pending;
    },

    load: function() {
        // Grab reference to table and summary numbers
        this.table = document.getElementById("results");
        this.passSpan = document.getElementById("passN");
        this.failSpan = document.getElementById("failN");
        this.pendingSpan = document.getElementById("pendingN");

        // Populate everything initially
        this.updateSummary();
        for (var i=0; i<this.tests.length; ++i) {
            var tr = document.createElement("tr");
            tr.id = "test" + i;
            tr.appendChild(document.createElement("td"));
            tr.appendChild(document.createElement("td"));
            tr.appendChild(document.createElement("td"));
            this.table.appendChild(tr);
            this.tests[i].setRow(tr.id);
            this.tests[i].draw();
        }
    },

    run: function() {
        this.currTest = 0;
        this.runNextTest();
    },

    runNextTest: function() {
        this.updateSummary();
        var i = this.currTest++;
        if (i >= this.tests.length) return;
        
        var self = this;
        this.tests[i].oncomplete = function() {
            self.runNextTest();
        }
        this.tests[i].run();
    }
}

if (window.addEventListener) {
    window.addEventListener("load", function() { TestArray.load(); } );
} else {
    window.attachEvent("onload", function() { TestArray.load(); } );
}


var alive = false;
function start() {
    if (!alive) { return; }
    TestArray.run();
    document.getElementById("start").style.display = "none";
    document.getElementById("resultDiv").style.display = "inline";
}

/**
 * The util. version uses a Uint8Array constructor, which does not work with
 * the proxy ArrayBufferView object that Firefox passes to the content page.
 */
function abv2hex (abv) {
    var hex = "";
    for (var i = 0; i < abv.length; ++i) {
        var zeropad = (abv[i] < 0x10) ? "0" : "";
        hex += zeropad + abv[i].toString(16);
    }
    return hex;
}
function memcmp(x, y) {
    if (x.length != y.length) { return false; }
    for (var i = 0; i < x.length; ++i) {
        if (x[i] !== y[i]) { return false; }
    }
    return true;
}

if (window.polycrypt.polyfill) {
    window.polycrypt.onalive = function() { alive = true; };
} else {
    util.memcmp = memcmp;
    util.abv2hex = abv2hex;
    window.onload = function() { alive = true; };
}
