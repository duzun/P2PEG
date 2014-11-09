/**
 *  This file is under devekioment.
 *
 *  @TODO: all ???
 *
 *  @author DUzun.Me
 */

var sha1   = require('./lib/sha1.js');
var base64 = require('./lib/base64.js');

;(function $_P2PEG(root, Function, String, Date, Math) {
    // -------------------------------------------------
    ;(Date.now instanceof Function) || (Date.now = function now() { return +(new Date) });
    // -------------------------------------------------
    var undefined
    ,   version = '0.2.3'
    ,   INT_SIZE = 4
    ,   start_ts = Date.now()
    ,   _instance
    ,   int_len = Math.round(INT_SIZE * Math.log10(256))
    ,   P2PEG = function (secret) {
            // Private
            var _opad, _ipad

            ,   _state
            ,   _state_mtime

            ,   _clientEntropy
            ,   _serverEntropy
            ,   _serverEEntropy
            ,   _filesystemEntropy

            ,   _b = ''
            ,   _l = 0

            ,   _self = this
            ;

            // __construct()
            if ( secret == undefined ) {
                secret = ',!8L_J:UW~l\'ACt:7c05!R9}~>yb!gPP=|(@FBny\'ao/&-\jVs';
            }

            _self.setSecret(secret);

            _self.seedSys = _self.isServer();
        }

    ,   proto = P2PEG.prototype
    ;

    // -------------------------------------------------
    // Static
    P2PEG.version = version;

    /// Get the singleton instance
    P2PEG.instance = function instance(secret) {
        if(!_instance) {
            _instance = new P2PEG(secret);
        }
        return _instance;
    }

    // -------------------------------------------------
    proto.constructor = P2PEG;

    proto.setSecret = function setSecret(secret) {
        // ???
    }

    // -------------------------------------------------
    proto.seed = function seed(_seed) {
        // ???
    }

    // -------------------------------------------------
    /**
     *  Return a random binary string of specified length.
     */
    proto.str = function str(len) {
        // ???
    }

    /**
     *  Hex encoded string
     */
    proto.hex = function hex(len) {
        var l = len != undefined ? len / 2 : undefined
        ,   ret = this.str(l)
        ;
        return bin2hex(ret);
    }

    /**
     *  Base64 encoded text for URL
     */
    proto.text = function text(len) {
        var l = len != undefined ? ceil(len * 3.0 / 4.0) : undefined
        ,   ret = bin2text(this.str(l))
        ;
        if(len != undefined && ret.length > len) ret = ret.substr(0, len);
        return ret;
    }

    /**
     *  Return a random 16 bit integer.
     *
     *  @return (int)random
     */
    proto.int16 = function int16() {
        return this.int(2);
    }

    /**
     *  Return a random 32 bit integer.
     *
     *  @return (int)random
     */
    proto.int32 = function int32() {
        return this.int(4);
    }

    /**
     *  Return a random integer.
     *
     *  @param (int)$size - number of bytes used to generate the integer [1..INT_SIZE].
     *                      Defaults to INT_SIZE (4 or 8, depending on system)
     *      Ex. If $size == 1, the result is a number from interval [0..255].
     *          If $size == 3, the result is a number from interval [0..16777215].
     *
     *  @return (int)random
     *
     */
    proto.int = function _int(size) {
        var s = size != undefined ? size : INT_SIZE
        ,   src = this.str(s)
        ,   r = 0
        ;
        for(;s--;) r = (r << 8) | src.charCodeAt(s);
        return r;
    }

    // -------------------------------------------------
    /**
     *  Pseudo-random 32bit integer numbers generator.
     *
     *  This function produces same result as $this->int32(),
     *  but is much faster at generating long strings of random numbers.
     *
     *  @source http://en.wikipedia.org/wiki/Random_number_generation
     */
    proto.rand32 = function rand32() {
        var _self = this
        ,   rs_w = _self_self.rs_w
        ,   rs_z = _self_self.rs_z
        ;

        // Seed if necessary
        while(!rs_w || rs_w == 0x464fffff) {
            /* must not be zero, nor 0x464fffff */
            rs_w = _self.int32() ^ _self.int32();
            // rs_w = (D.now()*M.random())>>>0; // alternative
        }
        while(!rs_z || rs_z == 0x9068ffff) {
            /* must not be zero, nor 0x9068ffff */
            rs_z = _self.int32() ^ _self.int32();
            // rs_z = (D.now()*M.random())>>>0; // alternative
        }

        rs_z = 36969 * (rs_z & 0xFFFF) + (rs_z >> 16);
        rs_w = 18000 * (rs_w & 0xFFFF) + (rs_w >> 16);
        var ret = (rs_z << 16) + rs_w;  /* 32-bit result */

        _self.rs_w = rs_w;
        _self.rs_z = rs_z;

        return ret;
    }

    proto.saveState = function saveState(sf) {
        // ???
    }

    proto.hash = function hash(str, raw) {
        if( raw === undefined ) raw = true; // default
        // ???
    }

    proto.isServer = function isServer() {
        // ???
    }

    proto.seedSys = true;
    proto.rs_z = 0;
    proto.rs_w = 0;

    // -------------------------------------------------
    // Helpers:
    var str_repeat = function str_repeat(str, n) {
        var r = ''; while(n-->0) r += str; return r;
    };

    var floor = Math.floor;
    var ceil  = Math.ceil;

    /// Returns hex representation of the string
    /// If this is UTF8, it gets converted
    var bin2hex = function bin2hex(s, encodeUtf8) {
        var ret = ''
        ,   i = 0
        ,   l = s.length
        ,   c
        ;
        for (; i<l; i++) {
            c = s.charCodeAt(i);
            // if(encodeUtf8 && c > 0xFF) return hex.call(s.utf8Encode()); //??? todo
            if(c < 16) ret += '0';
            ret += c.toString(16);
        }
        return ret;
    }'

    /// Converts a string of HEX digits (0-f) to its binary string representation
    var hex2bin = function hex2bin(s) {
        var ret = []
        ,   i = 0
        ,   l = s.length
        ,   c, k
        ;
        for ( ; i < l; i += 2 ) {
            c = parseInt(s.substr(i, 1), 16);
            k = parseInt(s.substr(i+1, 1), 16);
            if(isNaN(c) || isNaN(k)) return false;
            ret.push( (c << 4) | k );
        }
        return _.fromCharCode.apply(_, ret);
    };

    var bin2text = function bin2text(bin) {
        return base64.byteUrlEncode(bin);
    };

    var text2bin = function text2bin(text) {
        return base64.byteUrlDecode(text);
    };

    var strxor = function strxor($a,$b) {
        var a = $a ? String($a) : ''
        ,   b = $b ? String($b) : ''
        ,   m = a.length
        ,   n = b.length
        ,   ret = []
        ;
        if(m != n) {
            if(!m || !n) return a + b;
            if(n < m) {
                b = str_repeat(b, floor(m / n)) . b.substr(0, m % n);
                n = m;
            }
            else {
                a = str_repeat(a, floor(n / m)) . a.substr(0, n % m);
            }
        }
        for(m=0;m<n;m++) ret[m] = a.charCodeAt(m) ^ b.charCodeAt(m);
        return String.fromCharCode.apply(String, ret);
    };

    // -------------------------------------------------
    // Export:
    P2PEG.bin2text = bin2text;
    P2PEG.text2bin = text2bin;
    P2PEG.strxor   = strxor;

    this.P2PEG = P2PEG;

    // -------------------------------------------------
    if (typeof module != 'undefined' && module.exports) module.exports = P2PEG; // CommonJs export
    if (typeof define == 'function' && define.amd) define([], function() { return P2PEG; }); // AMD
    // -------------------------------------------------
})(this, Function, String, Date, Math);
