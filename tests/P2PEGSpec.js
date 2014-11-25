// -----------------------------------------------------
/**
 *  @author DUzun.Me
 *
 *  @TODO: Test the quality of generated data
 */
// -----------------------------------------------------
;(function (name, root) {
    'use strict';

    (typeof define == 'function' && define.amd
        ? define
        : (function (require) {
            return typeof module != 'undefined' && module.exports
                ? function (deps, factory) { module.exports = factory(require, module, require('../P2PEG')); }
                : function (deps, factory) { root[name] = factory(require, undefined, root.P2PEG); }
        }
        (typeof require == 'function' ? require : function (id){return root[id]}))
    )
    /*define*/(['require', 'module', '../P2PEG'], function (require, module, P2PEG) {

        var cons = P2PEG;

        describe("P2PEG static helpers", function () {
            it('should contain packInt($int)', function () {
                expect(typeof cons.packInt).toBe('function');
                expect(cons.packInt(0)).toBe("");
                expect(cons.packInt(-1)).toBe("");
                expect(cons.packInt(-1>>>1)).toBe("\xFF\xFF\xFF\x7F");
                expect(cons.packInt(parseInt('12345678', 16))).toBe("\x78\x56\x34\x12");
                expect(cons.packInt(parseInt('9ABCDEF', 16))).toBe("\xEF\xCD\xAB\x09");
            });
            it('should contain packFloat($float)', function () {
                expect(typeof cons.packFloat).toBe('function');
                var r = Math.random() * (-1>>>0);
                expect(cons.packFloat(r|0)).toBe(cons.packInt(r));
                expect(cons.packFloat(r)).not.toBe(cons.packInt(r));
            });
            it('should contain packIP4(ip)', function () {
                expect(typeof cons.packIP4).toBe('function');
                expect(cons.packIP4('1.0')).toBe("\x01\x00");
                expect(cons.packIP4('127.0.0.450')).toBe("\x7F\x00\x00\xC2");
                dump(cons.bin2hex(cons.packIP4(Math.PI)));
            });
        });

        describe("P2PEG", function () {
            cons.debug = true;

            var inst = cons.instance('Unit test');

            beforeEach(function() {
                inst && inst.seed('beforeEach');
            });

            afterEach(function() {
            });

            it("should have static method P2PEG::instance()", function () {
                expect(typeof cons.instance).toBe('function');
            });

            it("P2PEG:instance(secret) should return an instance of P2PEG", function () {
                inst = cons.instance('Unit test');
                expect(inst instanceof cons).toBeTruthy();
                expect(inst.constructor).toBe(cons);
            });

            dump(inst.hash(inst.dynEntropy(), false))

            inst = null;

        });

    });

}('P2PEGSpec', this));
