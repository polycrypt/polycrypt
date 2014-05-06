var log4js = (function console_log_wrapper() {
    'use strict';

    var printLog,
    doLogTrace = true,
    doLogDebug = true,
    doLogInfo  = true,
    doLogWarn  = true,
    doLogError = true;
    
    printLog = function log_print(label, msg, data, hasData) {
        var output = label +" :: "+ msg;
        if (hasData) { output += " :: " + JSON.stringify(data); }
        console.log(output);
    };  

    return {
        trace : doLogTrace ?
                function log_trace(msg, data) {
                    printLog("TRACE", msg, data, arguments.length > 1);
                } :
                function() { return; },

        debug : doLogDebug ?
                function log_trace(msg, data) {
                    printLog("DEBUG", msg, data, arguments.length > 1);
                } :
                function() { return; },

        info  : doLogInfo ?
                function log_trace(msg, data) {
                    printLog("INFO ", msg, data, arguments.length > 1);
                } :
                function() { return; },

        warn  : doLogWarn ?
                function log_trace(msg, data) {
                    printLog("WARN ", msg, data, arguments.length > 1);
                } :
                function() { return; },

        error : doLogError ?
                function log_trace(msg, data) {
                    printLog("ERROR", msg, data, arguments.length > 1);
                } :
                function() { return; },
    };
})();
