/**
 *  sha1 hash algorithm.
 *
 *  sha1(data: string[, isByteStream: bool]): hex string
 *
 *  'string'.sha1([isByteStream: bool]): hex string
 *
 *  if isByteStream is undefined,
 *      it defaults to TRUE if input string has multibyte chars
 *      and defaults to FALSE if input string doesn't have multibyte chars
 *
 *  @umd AMD, Browser, CommonJs, noDeps
 */
(function(name, root, String, Array) {
    'use strict';

    (typeof define !== 'function' || !define.amd
        ? typeof module == 'undefined' || !module.exports
            ? function (deps, factory) { root[name] = factory(); } // Browser
            : function (deps, factory) { module.exports = factory(); } // CommonJs
        : define // AMD
    )
    /*define*/(/*name, */[], function factory() {
        var rotateLeft = function(lValue, iShiftBits) {
                return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
            }

        ,   cvtHex = function(value) {
                for(var i = 7, v, ret = '';i >= 0;i--) {
                    v = (value>>>(i * 4))&0x0f;
                    ret += v.toString(16);
                }
                return ret;
            }

        ,   hasMultibyteRE = /[^\x00-\xFF]/

            /** Extend String object with method to encode multi-byte string to utf8
             *  - http://monsur.hossa.in/2012/07/20/utf-8-in-javascript.html */
        ,   utf8Encode = function(str) { return unescape( encodeURIComponent( str ) ); }

        /* Alternative:
        ,   utf8Encode = function(string) {
                string = string.replace(/\x0d\x0a/g, "\x0a");
                var output = "";
                for (var n = 0; n < string.length; n++) {
                    var c = string.charCodeAt(n);
                    if (c < 128) {
                        output += String.fromCharCode(c);
                    } else if ((c > 127) && (c < 2048)) {
                        output += String.fromCharCode((c >> 6) | 192);
                        output += String.fromCharCode((c & 63) | 128);
                    } else {
                        output += String.fromCharCode((c >> 12) | 224);
                        output += String.fromCharCode(((c >> 6) & 63) | 128);
                        output += String.fromCharCode((c & 63) | 128);
                    }
                }
                return output;
            }
        */

        ,   sha1 = function sha1(str, isByteStream) {
                var blockstart
                ,   i, j
                ,   W = new Array(80)
                ,   H0 = 0x67452301
                ,   H1 = 0xEFCDAB89
                ,   H2 = 0x98BADCFE
                ,   H3 = 0x10325476
                ,   H4 = 0xC3D2E1F0
                ,   A, B, C, D, E
                ,   tempValue
                ,   string = String(str)
                ,   stringLength = string.length
                ,   wordArray = []
                ,   ret
                ;
                if(isByteStream == undefined) {
                    isByteStream = !hasMultibyteRE.test(string);
                }
                if(!isByteStream) {
                    string = utf8Encode(string);
                }
                for(i = 0;i < stringLength - 3;i += 4) {
                    j = string.charCodeAt(i)<<24 | string.charCodeAt(i + 1)<<16 | string.charCodeAt(i + 2)<<8 | string.charCodeAt(i + 3);
                    wordArray.push(j);
                }
                switch(stringLength % 4) {
                    case 0:
                        i = 0x080000000;
                    break;
                    case 1:
                        i = string.charCodeAt(stringLength - 1)<<24 | 0x0800000;
                    break;
                    case 2:
                        i = string.charCodeAt(stringLength - 2)<<24 | string.charCodeAt(stringLength - 1)<<16 | 0x08000;
                    break;
                    case 3:
                        i = string.charCodeAt(stringLength - 3)<<24 | string.charCodeAt(stringLength - 2)<<16 | string.charCodeAt(stringLength - 1)<<8 | 0x80;
                    break;
                }
                wordArray.push(i);
                while((wordArray.length % 16) != 14 ) wordArray.push(0);
                wordArray.push(stringLength>>>29);
                wordArray.push((stringLength<<3)&0x0ffffffff);
                for(blockstart = 0;blockstart < wordArray.length;blockstart += 16) {
                    for(i = 0;i < 16;i++) W[i] = wordArray[blockstart+i];
                    for(i = 16;i <= 79;i++) W[i] = rotateLeft(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
                    A = H0;
                    B = H1;
                    C = H2;
                    D = H3;
                    E = H4;
                    for(i = 0;i <= 19;i++) {
                        tempValue = (rotateLeft(A, 5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
                        E = D;
                        D = C;
                        C = rotateLeft(B, 30);
                        B = A;
                        A = tempValue;
                    }
                    for(i = 20;i <= 39;i++) {
                        tempValue = (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
                        E = D;
                        D = C;
                        C = rotateLeft(B, 30);
                        B = A;
                        A = tempValue;
                    }
                    for(i = 40;i <= 59;i++) {
                        tempValue = (rotateLeft(A, 5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
                        E = D;
                        D = C;
                        C = rotateLeft(B, 30);
                        B = A;
                        A = tempValue;
                    }
                    for(i = 60;i <= 79;i++) {
                        tempValue = (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
                        E = D;
                        D = C;
                        C = rotateLeft(B, 30);
                        B = A;
                        A = tempValue;
                    }
                    H0 = (H0 + A) & 0x0ffffffff;
                    H1 = (H1 + B) & 0x0ffffffff;
                    H2 = (H2 + C) & 0x0ffffffff;
                    H3 = (H3 + D) & 0x0ffffffff;
                    H4 = (H4 + E) & 0x0ffffffff;
                }
                ret = cvtHex(H0) + cvtHex(H1) + cvtHex(H2) + cvtHex(H3) + cvtHex(H4);
                ret = ret.toLowerCase();
                return ret;
            }
        ;

        // Export to String.prototype.sha1
        sha1._proto_ =
        String.prototype.sha1 = function (isByteStream) { return sha1(this, isByteStream); }


        return sha1;
        // ---------------------------------------------------------------------------
    });

}('sha1', this, String, Array));


