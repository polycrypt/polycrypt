/*
 *
 *  Copyright 2013 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

function abv2latin1(abv) {
	String.fromCharCode.apply(null, abv);
};

function latin12abv(s) {
	var abv = new Uint8Array(s.length);
	var i = s.length;
	while (i--) {
		abv[i] = s.charCodeAt(i);
	}
	return abv;
};

var base64 = {
        stringify: function (a) {
            return btoa(String.fromCharCode.apply(0, a));
        },
        stringifyUrlSafe: function (a) {
            return base64.stringify(a).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        },
        parse: function (s) {
            s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, '');
            return new Uint8Array(Array.prototype.map.call(atob(s), function (c) { return c.charCodeAt(0) }));
        }
};

var latin1 = {
        stringify: function (a) {
            return String.fromCharCode.apply(0, a);
        },
        parse: function (s) {
            return new Uint8Array(Array.prototype.map.call(s, function (c) { return c.charCodeAt(0); }));
        }
};

var base16 = {
	stringify: function (a) {
		return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
	},
	parse: function (s) {
		return new Uint8Array(s.match(/(..)/g).map(function (s) { return parseInt(s, 16); }));
	}
};

var utf8 = {
	stringify: function (a) {
		decodeURIComponent(escape(latin1.stringify(a)));
	},
	parse: function (s) {
		return latin1.parse(unescape(encodeURIComponent(s)));
	}
};


//Convert a hex string to an ArrayBufferView
function hex2abv(hex) {
	if (hex.length % 2 != 0) {
		throw new Error('bad hex');
	}
	var abv = new Uint8Array(hex.length / 2);
	for (var i = 0; i < abv.length; ++i) {
		abv[i] = parseInt(hex.substr(2 * i, 2), 16);
	}
	return abv;
};

//Convert a ArrayBufferView to hex string
var HEX_MAP = '0123456789abcdef';
function abv2hex(abv) {
	var s = '',
	b,
	length = abv.length;
	for (var i = 0; i < length; i++) {
		b = abv[i];
		s += HEX_MAP[b >> 4] + HEX_MAP[b & 0x0F];
	}
	return s;
};

function abv2u8(abv) {
	return new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
}
var b64a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
/*** Convert between ArrayBufferView and Base64url encoding ***/
function b64encode(abv) {
    var u8 = abv2u8(abv);
	var b64 = "";

	var i = 0;
	while (i < u8.length - 2) {
		var x1 = u8[i++], x2 = u8[i++], x3 = u8[i++];
		b64 += b64a.charAt(x1 >> 2) +
		b64a.charAt(((x1 & 3) << 4) | (x2 >> 4)) +
		b64a.charAt(((x2 & 15) << 2) | (x3 >> 6)) +
		b64a.charAt(x3 & 63);
	}
	if (i === u8.length - 2) {
		var x1 = u8[i++], x2 = u8[i++];
		b64 += b64a.charAt(x1 >> 2) +
		b64a.charAt(((x1 & 3) << 4) | (x2 >> 4)) +
		b64a.charAt(((x2 & 15) << 2)) +
		"=";
	} else if (i === u8.length - 1) {
		var x1 = u8[i++];
		b64 += b64a.charAt(x1 >> 2) +
		b64a.charAt(((x1 & 3) << 4)) +
		"==";
	}

	return b64;
}

function b64encodeUrlSafeNoPadding(abv) {
	// used in JWE
	// described in http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C
	var s = b64encode(abv);
	s = s.split('=')[0]; // Remove any trailing '='s
	s = s.replace('+', '-'); // 62nd char of encoding
	s = s.replace('/', '_'); // 63rd char of encoding
	return s;
};

function b64decode(b64) {
	console.log("running b46decode()");
    
    var u8 = [];
	b64 = b64.replace(/[^A-Za-z0-9\+/-]/g, "");

	var i = 0;
	while (i < b64.length) {
		var x1 = b64a.indexOf(b64[i++]);
		var x2 = b64a.indexOf(b64[i++]);
		var x3 = b64a.indexOf(b64[i++]);
		var x4 = b64a.indexOf(b64[i++]);

		var y1 = (x1 << 2) | (x2 >> 4);
		var y2 = ((x2 & 15) << 4) | (x3 >> 2);
		var y3 = ((x3 & 3) << 6) | x4;

		u8.push(y1);
		if (0 <= x3 && x3 < 64) { u8.push(y2); }
		if (0 <= x4 && x4 < 64) { u8.push(y3); }
	}

	return new Uint8Array(u8);
}

/**
 * URL-safe Base64 encode data as UTF-8 without padding characters.
 * 
 * @param {string|Uint8Array} data the value to Base64 encode.
 * @return {Uint8Array} the Base64 encoded data.
 */

function b64urlEncode(data) {
    if (typeof data == 'string')
       // data = textEncoding$getBytes(data, "utf-8");
    	data = utf8.parse(data);
    //var padded = base64$encode(data, true);
    var padded = base64.stringify(data);
    var padIndex = padded.indexOf('.');
    return (padIndex != -1) ? padded.substring(0, padIndex) : padded;
}

/**
 * URL-safe Base64 decode data that has no padding characters.
 * 
 * @param {string} data the Base64 encoded data.
 * @return {Uint8Array} the decoded data.
 */
function b64urlDecode(data) {
    var toPad = 4 - (data.length % 4);
    if (toPad == 0 || toPad == 4)
       // return base64$decode(data);
       return base64.parse(data);
    var padded = data;
    for (var i = 0; i < toPad; ++i)
        padded += '.';
    return base64$decode(padded);
    //return base64.parse(padded);
}

/**
 * @param {Uint8Array} bytes encoded data
 * @param {string=} encoding "utf-8", "utf-16" (default="utf-8")
 *
 * @returns {string}
 */
function textEncoding$getString(bytes, encoding) {
    if (!encoding || encoding === "utf-8") {
        return utf8$getString(bytes);
    	//return utf8.stringify(bytes);
    }
    throw new Error("unsupported encoding");
};

/**
 * @param {Uint8Array} bytes encoded data
 *
 * @returns {string}
 */
function utf8$getString(bytes) {
    var i = 0,
        charCode,
        bytesLength = bytes.length,
        str = "";

    while(i < bytesLength) {
        charCode = bytes[i++];

        // check the first flag, which indicates that this is a multi-byte character
        if (charCode & 0x80) {
            // 1xxxxxxx
            if ((charCode & 0xE0) === 0xC0) {
                // 110xxxxx	10xxxxxx
                charCode = ((charCode & 0x1F) << 6) + (bytes[i++] & 0x3F);
            } else if ((charCode & 0xF0) === 0xE0) {
                // 1110xxxx	10xxxxxx 10xxxxxx
                charCode = ((charCode & 0x0F) << 12) + ((bytes[i++] & 0x3F) << 6) + (bytes[i++] & 0x3F);
            } else {
                // 1111xxxx	10xxxxxx 10xxxxxx 10xxxxxx (or more)
                // JavaScript only rupports 2 byte characters
                throw new Error("unsupported character");
            }
        }

        str += String.fromCharCode(charCode);
    }

    return str;
};

var map =    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
urlmap = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
padchar =    '=',
urlpadchar = '.',
charNumber1 = { },
charNumber2 = { },
charNumber3 = { '=': 0, '.': 0 },
charNumber4 = { '=': 0, '.': 0 },
prepRegex = /\s*/g,
checkRegex = new RegExp('^[' + map + '-_]*[' + padchar + urlpadchar + ']{0,2}$');

var i = map.length;
while (i--) {
	// pre-calculate values for each of quad-s
	charNumber1[map[i]] = i * 0x40000;
	charNumber2[map[i]] = i * 0x1000;
	charNumber3[map[i]] = i * 0x40;
	charNumber4[map[i]] = i;
}
var j = urlmap.length;
while (j--) {
	// stop once we've already seen this character
	if (map[j] == urlmap[j]) break;
	// pre-calculate values for each of quad-s
	charNumber1[urlmap[j]] = j * 0x40000;
	charNumber2[urlmap[j]] = j * 0x1000;
	charNumber3[urlmap[j]] = j * 0x40;
	charNumber4[urlmap[j]] = j;
}

/**
 * Base64 decode a string.
 *
 * @param {String} a Base64 string representation of data.
 * @return {Uint8Array} the decoded data.
 * @throws Error if the Base64 string is the wrong length or is not Base64
 *         encoded data.
 */
base64$decode = function (s) {
    s = s.replace(prepRegex, '');

    var l = s.length,
        triplet;

    if (l % 4 != 0 || !checkRegex.test(s))
        throw new Error('bad base64: ' + s);

    var aLength = (l / 4) * 3 -
            ((s[l - 1] == padchar || s[l - 1] == urlpadchar) ? 1 : 0) -
            ((s[l - 2] == padchar || s[l - 2] == urlpadchar) ? 1 : 0),
        a = new Uint8Array(aLength),
        si = 0,
        ai = 0;

    while (si < l) {
        triplet =
            charNumber1[s[si++]] +
            charNumber2[s[si++]] +
            charNumber3[s[si++]] +
            charNumber4[s[si++]];

        a[ai++] = (triplet >>> 16);
        if (ai < aLength) {
            a[ai++] = (triplet >>> 8) & 0xFF;
            if (ai < aLength) {
                a[ai++] = (triplet) & 0xFF;
            }
        }
    }

    return a;
};


