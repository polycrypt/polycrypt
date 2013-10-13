/* PostMessage Protocol */
/*
{
    cookie:  PC_MAGIC_COOKIE // REQUIRED
    src:     // front | back REQUIRED
    opid:    // operation id OPTIONAL
    method:  // method name REQUIRED
    args:    // arguments to the method OPTIONAL
    event:   // event to fire
    local:   // whether to stop here (bool) OPTIONAL DEFAULT FALSE
    toFront: // direction back->front OPTIONAL DEFAULT FALSE
    toBack:  // direction front->back OPTIONAL DEFAULT FALSE
}
*/
var PCMessage = {
    PC_MAGIC_COOKIE: "PolyCrypt-21A30E0E-1048-4ED0-BF7A-B1E01CA328E9",

    create: function PCMessage_create(partial) {
        var full = partial || {};
        full.cookie = this.PC_MAGIC_COOKIE;
        return full;
    },

    valid: function PCMessage_valid(msg) {
        return (
            (typeof(msg) === 'object') &&
            (msg.hasOwnProperty('cookie')) &&
            (msg.cookie === this.PC_MAGIC_COOKIE) &&
            (msg.hasOwnProperty('method') || msg.hasOwnProperty('event'))
        );
    },
};
