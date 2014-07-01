// Non-crypto Utilities
// -- Conversion between ArrayBuffer and other formats
//     -- To/from hex string
//     -- To/from SJCL bitArray
//     -- To/from CryptoJS wordArray
//     -- To/from JavaScript (UTF-16) string

var util = {
    // Detect when an object is an ArrayBufferView
    isABV: function util_isABV(x) {
        return  (
            (x instanceof Int8Array) ||
            (x instanceof Uint8Array) ||
            (x instanceof Int16Array) ||
            (x instanceof Uint16Array) ||
            (x instanceof Int32Array) ||
            (x instanceof Uint32Array) ||
            (x instanceof Float32Array) ||
            (x instanceof Float64Array) ||
            ((typeof(x) == 'object') && ('buffer' in x) && 
             ('byteLength' in x) && ('byteOffset' in x))
        );
    },

    // Throw an exception if an assertion fails
    assert: function util_assert(value) {
        if (console && console.trace) { console.trace(); }
        if (!value) { throw "Assertion failed"; }
    },

    // Reverse the byte order in a 4-byte integer
    htonl: function util_htonl(x) {
        return (x >> 24) +
               (((x >> 16) % 256) << 8) +
               (((x >> 8) % 256) << 16) +
               ((x % 256) << 24);
    },

    // Compare the contents of two ArrayBufferViews
    memcmp: function util_memcmp(x, y) {
        this.assert( this.isABV(x) );
        this.assert( this.isABV(y) );

        if (x.byteLength !== y.byteLength) { return false; }

        var xb = new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
        var yb = new Uint8Array(y.buffer, y.byteOffset, y.byteLength);
        for (var i=0; i<xb.byteLength; ++i) {
            if (xb[i] !== yb[i]) {
                return false;
            }
        }
        return true;
    },

    // Convert an ArrayBufferView to a hex string
    // Hex strings will be our medium of exchange with libraries, it seems
    abv2hex: function util_abv2hex(abv) {
        var b = new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
        var hex = "";
        for (var i=0; i <b.length; ++i) {
            var zeropad = (b[i] < 0x10) ? "0" : "";
            hex += zeropad + b[i].toString(16);
        }
        return hex;
    },

    // Convert a hex string to an ArrayBufferView
    hex2abv: function util_hex2abv(hex) {
        if (hex.length % 2 !== 0) {
            hex = "0" + hex;
        }

        var abv = new Uint8Array(hex.length / 2);
        for (var i=0; i<abv.length; ++i) {
            abv[i] = parseInt(hex.substr(2*i, 2), 16);
        }
        return abv;
    },


    /*** Conversion with SJCL bitArray ***/
    ba2abv: function util_ba2abv(ba) {
        return this.hex2abv(sjcl.codec.hex.fromBits(ba));
    },
    abv2ba: function util_abv2ba(abv) {
        return sjcl.codec.hex.toBits(this.abv2hex(abv));
    },

    /*** Conversion with CryptoJS wordArray ***/
    wa2abv: function util_wa2abv(wa) {
        return this.hex2abv(CryptoJS.enc.Hex.stringify(wa));
    },
    abv2wa: function util_abv2ba(abv) {
        return CryptoJS.enc.Hex.parse(this.abv2hex(abv));
    },


    /*** Conversion with UTF-16 strings ***/
    str2abv: function util_str2abv(str)
    {
        var abv = new Uint16Array(str.length);
        for (var i=0; i<str.length; ++i) {
            abv[i] = str.charCodeAt(i);
        }
        return abv;
    },
    abv2str: function util_abv2str(abv)
    {
        if (abv.byteLength % 2 !== 0) {
            throw new Exception("UTF-16 decoding error");
        }
        var u16 = new Uint16Array(abv.buffer, abv.byteOffset, abv.byteLength/2);
        var str = "";
        for (var i=0; i<u16.length; ++i) {
            str += String.fromCharCode(u16[i]);
        }
        return str;
    },

    /*** Conversion with UTF-8 strings ***/
    u82abv: function util_u82abv(str)
    {
        var abv = new Uint8Array(str.length);
        for(var i = 0; i < str.length; ++i)
        {
            abv[i] = str.charCodeAt(i);
        }
        return abv;
    },
    abv2u8: function util_abv2u8(abv)
    {
        return new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
    },

    /*** Convert between ArrayBufferView and Base64url encoding ***/
    b64a: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=",
    b64encode: function util_b64encode(abv) {
        var u8 = this.abv2u8(abv);
        var b64 = "";
    
        var i=0;
        while (i < u8.length - 2) {
            var x1 = u8[i++], x2 = u8[i++], x3 = u8[i++];
            b64 += this.b64a.charAt( x1 >> 2 ) +
                 this.b64a.charAt( ((x1 &  3) << 4) | (x2 >> 4) ) +
                 this.b64a.charAt( ((x2 & 15) << 2) | (x3 >> 6) ) +
                 this.b64a.charAt( x3 & 63 );
        }
        if (i === u8.length - 2) {
            var x1 = u8[i++], x2 = u8[i++];
            b64 += this.b64a.charAt( x1 >> 2 ) +
                 this.b64a.charAt( ((x1 &  3) << 4) | (x2 >> 4) ) +
                 this.b64a.charAt( ((x2 & 15) << 2) ) +
                 "=";
        } else if (i === u8.length - 1) {
            var x1 = u8[i++];
            b64 += this.b64a.charAt( x1 >> 2 ) +
                 this.b64a.charAt( ((x1 &  3) << 4) ) +
                 "==";
        }

        return b64;
    },
    b64decode: function util_b64decode(b64) {
        var u8 = [];
        b64 = b64.replace(/[^A-Za-z0-9\=_-]/g, "");

        var i=0;
        while (i < b64.length) {
            var x1 = this.b64a.indexOf( b64[i++] );
            var x2 = this.b64a.indexOf( b64[i++] );
            var x3 = this.b64a.indexOf( b64[i++] );
            var x4 = this.b64a.indexOf( b64[i++] );
            
            var y1 = (x1 << 2) | (x2 >> 4);
            var y2 = ((x2 & 15) << 4) | (x3 >> 2);
            var y3 = ((x3 & 3) << 6) | x4;

            u8.push( y1 );
            if ( 0 <= x3 && x3 < 64 ) { u8.push(y2); }
            if ( 0 <= x4 && x4 < 64 ) { u8.push(y3); }
        }

        return new Uint8Array(u8);
    },
    
    /*** Join or split ArrayBufferViews ***/
    abvcat: function util_abvcat(abv1, abv2) {
        var abv = new Uint8Array(abv1.byteLength + abv2.byteLength);
        abv.set(this.abv2u8(abv1), 0);
        abv.set(this.abv2u8(abv2), abv1.byteLength);
        return abv;
    },
    abvsplit: function util_abvsplit(abv, i) {
        var abv8 = this.abv2u8(abv);
        return [
            this.abv2u8( abv8.subarray(0,i) ),
            this.abv2u8( abv8.subarray(i) )
        ];
    }
};
