<?php
// -----------------------------------------------------
/**
 *  @author DUzun.Me
 *
 *  @TODO: Test the quality of generated data
 */
// -----------------------------------------------------
require_once dirname(dirname(__FILE__)) . '/P2PEG.php';
// -----------------------------------------------------
// Surogate class for testing, to access protected attributes of P2PEG
class TestP2PEG4Tests extends P2PEG {
    public function _t4t_getClientEntropy() { return $this->_clientEntropy; }
    public function _t4t_getServerEntropy() { return $this->_serverEntropy; }
    public function _t4t_getServerEEntropy() { return $this->_serverEEntropy; }
    public function _t4t_getFilesystemEntropy() { return $this->_filesystemEntropy; }

    static function _t4t_get_int_len() { return self::$int_len; }

}
// -----------------------------------------------------

class TestP2PEG extends PHPUnit_Framework_TestCase {
    // -----------------------------------------------------
    static public $inst;
    static public $className = 'P2PEG';
    static public $testName;
    static public $log = true;

    // Before any test
    static public function setUpBeforeClass() {
        self::$inst = new TestP2PEG4Tests('Unit test');
    }

    // After all tests
    static public function tearDownAfterClass() {
        $state_file = self::$inst->state_file;

        self::$inst = NULL;

        empty($state_file) or unlink($state_file);
    }


    // Before every test
    public function setUp() {
        self::$inst->seed(__FUNCTION__);
        self::$testName = $this->getName();
    }

    // After every test
    public function tearDown() {
    }

    // -----------------------------------------------------
    // public function testPlay() {
        // var_export(hex2bin('7465737'));
    // }
    // -----------------------------------------------------

    public function testClass() {
        $this->assertClassHasStaticAttribute('version' , self::$className);
        $this->assertClassHasStaticAttribute('start_ts', self::$className);
        $this->assertClassHasAttribute('state_file', self::$className);
        $this->assertClassHasAttribute('seedSys'   , self::$className);
    }

    // -----------------------------------------------------
    public function testInstanceMethod() {
        $o = call_user_func(array(self::$className, 'instance'));
        $this->assertContainsOnlyInstancesOf(
            self::$className
            , array($o)
            , self::$className.'::instance() returns an object'
        );
    }

    // -----------------------------------------------------
    public function testHash() {
        self::$inst->setSecret('secret 1');
        $h1  = self::$inst->hash('test', true);
        $h1r = self::$inst->hash('test', false);

        self::log('hash ==', var_export(self::$inst->hash, true));

        $this->assertGreaterThan(0, strlen($h1), 'raw hash is empty');
        $this->assertGreaterThan(0, strlen($h1r), 'hash is empty');
        $this->assertRegExp('#[^0-9a-fA-F]#', $h1, "hash('test', true) doen't seem to be raw");
        $this->assertNotRegExp('#[^0-9a-fA-F]#', $h1r, "hash('test', false) is not hex");

        self::$inst->setSecret('secret 2');
        $h2 = self::$inst->hash('test', true);

        $this->assertNotEquals($h1, $h2, 'Secret change did not affect hash()');
    }

    // -----------------------------------------------------
    public function testBinTextConv() {
        $str     = self::$inst->str();
        $text    = self::$inst->bin2text($str);
        $text2   = self::$inst->bin2text($text);
        $untext2 = self::$inst->text2bin($text2);
        $untext  = self::$inst->text2bin($untext2);

        $this->assertNotEquals($str, $text);
        $this->assertNotEquals($text, $text2);
        $this->assertEquals($str, $untext);
        $this->assertEquals($text, $untext2);
    }

    // -----------------------------------------------------
    public function testPackIP4() {
        $o = self::$inst;

        $this->assertEquals($o->packIP4('not a number at all'), false);
        $this->assertEquals($o->packIP4('N.a.N.with.dots'), false);
        $this->assertEquals($o->packIP4('24.is.a.number.like.87.is'), "\x18\x57");
        $this->assertEquals($o->packIP4('1.0'), "\x01\x00");
        $this->assertEquals($o->packIP4('127.0.255.450'), "\x7F\x00\xFF\xC2");
        $this->assertEquals($o->packIP4('1.2.3.4.5.6'), "\x01\x02\x03\x04\x05\x06");
        $this->assertEquals(substr($o->packIP4(M_PI), 0,1), "\x03");
        $this->assertEquals($o->packIP4(3.141), "\x03\x8D");

        $this->assertEquals(
            $o->packIP4('127.128.255.0.127.128.255.0')
            , "\x7F\x80\xff\x00\x7F\x80\xff\x00"
        );
    }

    public function testPackInt() {
        $o = self::$inst;

        $this->assertEquals($o->packInt(0), '', 'packInt(0) should return ""');
        $this->assertEquals($o->packInt(-1), '', 'packInt(-1) should return ""');
        $this->assertEquals($o->packInt(0x1FFFFFFFFFFFFF), "\xFF\xFF\xFF\xFF\xFF\xFF\x1F", 'packInt(0x1FFFFFFFFFFFFF) should handle numbers bigger then int32');
        if ( PHP_INT_SIZE == 4 ) {
            // self::log(dechex((PHP_INT_MAX*2)+1));
            // self::log(dechex(0xFFFFFFFF));
            $this->assertEquals($o->packInt(0xFFFFFFFF), "\xFF\xFF\xFF\xFF", 'packInt(0xFFFFFFFF) should handle max unsigned int32');
        }

        $this->assertEquals($o->packInt(1234567890), "\xd2\x02\x96\x49");
        $this->assertEquals($o->packInt(PHP_INT_MAX), str_repeat("\xFF", PHP_INT_SIZE-1)."\x7F");

        $longStrNumber = '1234567890123456789012345678901234567890';
        $bin = $o->packInt($longStrNumber);
        $int_len = round(PHP_INT_SIZE * log10(256));

        $this->assertNotEmpty($bin);
        $this->assertGreaterThan(strlen($longStrNumber) / $int_len * PHP_INT_SIZE - 1, strlen($bin));

        $b123 = $o->packInt(12345);
        $this->assertEquals($b123, $o->packInt(12345.6789));
        $this->assertEquals($b123, $o->packInt('12345.6789'));
        $b123 = $o->packInt(98765);
        $this->assertEquals($b123, $o->packInt(98765.5321));
        $this->assertEquals($b123, $o->packInt('98765.5321'));

        $this->assertTrue(0 != strncmp($o->packInt('512985229146'), "\xFF\xFF", 2));
    }

    public function testPackFloat() {
        $o = self::$inst;

        $r = (float)rand() / getrandmax() * 0xFFFFFFFF;
        $b = $o->packInt($r);
        $this->assertEquals($o->packFloat($r|0), $b);
        $this->assertNotEquals($o->packFloat($r), $b);
    }


    // -----------------------------------------------------
    public function testInt() {
        // int()
        $int1 = self::$inst->int();
        $int2 = self::$inst->int();
        $s1 = '0x'.dechex($int1);
        $s2 = '0x'.dechex($int2);
        self::log("int()\t->", $s1. ",\tint()\t->", $s2);

        $this->assertEquals(is_int($int1), true, 'int() should return (int)');
        $this->assertEquals(is_int($int2), true, 'int() should return (int)');
        $this->assertNotEquals($int2, $int1, 'int() should return different numbers');
        $this->assertNotEquals(($int1 | $int2) & (0xFF<<((PHP_INT_SIZE-1)<<3)), 0, 'int() returned a too small value');

        for ($i = PHP_INT_SIZE; --$i;) {
            // It could happen that an int(1) is 0, but there is a very little
            // posibility to have 5 consecutive 0 of int(1)
            $count = 5;
            do {
                $int = self::$inst->int($i);
                if ( $count-- <= 0 ) break;
            } while(!$int);
            $this->assertNotEmpty($int, "int($i) should not be empty");
            $m = (-1<<($i<<3));
            $this->assertEmpty($int & $m, "int($i) should not return more then $i bytes: ".dechex($int));
        }

        // int16()
        $intA1 = self::$inst->int16();
        $intA2 = self::$inst->int16();
        $s1 = '0x'.dechex($intA1);
        $s2 = '0x'.dechex($intA2);
        self::log("int16()\t->", $s1. ",\tint16()\t->", $s2);

        $this->assertEquals(is_int($intA1), true, 'int16() should return (int)');
        $this->assertEquals(is_int($intA2), true, 'int16() should return (int)');
        $this->assertNotEquals($intA2, $intA1, 'int16() should return different numbers');
        $m = (-1<<(2<<3));
        $this->assertEmpty(($t = $intA1 & $m) ? $t ^ $m : $t, "int16() should not return more then 2 bytes: $intA1 ".dechex($intA1));
        $this->assertEmpty(($t = $intA2 & $m) ? $t ^ $m : $t, "int16() should not return more then 2 bytes: $intA2 ".dechex($intA2));

        // int32()
        $intB1 = self::$inst->int32();
        $intB2 = self::$inst->int32();
        $s1 = '0x'.dechex($intB1);
        $s2 = '0x'.dechex($intB2);
        self::log("int32()\t->", $s1. ",\tint32()\t->", $s2);

        $this->assertEquals(is_int($intB1), true, 'int32() should return (int)');
        $this->assertEquals(is_int($intB2), true, 'int32() should return (int)');
        $this->assertNotEquals($intB2, $intB1, 'int32() should return different numbers');
        $m = (-1<<(2<<3));
        $this->assertNotEmpty($intB1 & $m, "int32() should not return less then 2 bytes: $intB1 ".dechex($intB1));
        $this->assertNotEmpty($intB2 & $m, "int32() should not return less then 2 bytes: $intB2 ".dechex($intB2));

        // rand32()
        $intC1 = self::$inst->rand32();
        $intC2 = self::$inst->rand32();
        $s1 = '0x'.dechex($intC1);
        $s2 = '0x'.dechex($intC2);
        self::log("rand32() ->", $s1. ",\trand32() ->", $s2);

        $this->assertEquals(is_int($intC1), true, 'rand32() should return (int) '.gettype($intC1));
        $this->assertEquals(is_int($intC2), true, 'rand32() should return (int) ');
        $this->assertNotEquals($intC2, $intC1, 'rand32() should return different numbers');
        $m = (-1<<(2<<3));
        $this->assertNotEmpty($intC1 & $m, "rand32() should not return less then 2 bytes: $intC1 ".dechex($intC1));
        $this->assertNotEmpty($intC2 & $m, "rand32() should not return less then 2 bytes: $intC2 ".dechex($intC2));
    }

    // -----------------------------------------------------
    public function testStr() {
        $s1  = self::$inst->str();
        $s2  = self::$inst->str();
        $len = strlen($s2);

        // self::log("str() ->", substr($s1, 0, 48). '...');
        self::log('strlen(str()) ==', $len);

        $this->assertNotEquals($s1, $s2, 'str() should return different result at each call');
        $this->assertNotEmpty($s1, 'str() should never return empty result');
        $this->assertNotEmpty($s2, 'str() should never return empty result');
        $this->assertNotEmpty(preg_match('/[^\x08-\x80]/', $s2), 'str() should have non-ASCII chars');

        $s1l = $len - 10; // less then $len, from begining
        $s2l = 5;         // buffer has more data then we need
        $s3l = 8;         // buffer has less data then we need
        $s4l = 3*$len;    // buffer + seed more times
        $s1 = self::$inst->str($s1l);
        $s2 = self::$inst->str($s2l);
        $s3 = self::$inst->str($s3l);
        $s4 = self::$inst->str($s4l);

        $this->assertNotEmpty($s1, "str({$s1l}) should never return empty result");
        $this->assertNotEmpty($s2, 'str() should never return empty result');
        $this->assertEquals(strlen($s1), $s1l, "str({$s1l}) returned different length: ".strlen($s1));
        $this->assertEquals(strlen($s2), $s2l, "str({$s2l}) returned different length: ".strlen($s2));
        $this->assertEquals(strlen($s3), $s3l, "str({$s3l}) returned different length: ".strlen($s3));
        $this->assertEquals(strlen($s4), $s4l, "str({$s4l}) returned different length: ".strlen($s4));
    }

    // -----------------------------------------------------
    public function testText() {
        $s1  = self::$inst->text();
        $s2  = self::$inst->text();
        $len = strlen($s2);

        self::log("text() ->", substr($s2, 0, 48). '...');
        self::log('strlen(text()) ==', $len);

        $this->assertNotEquals($s1, $s2, 'text() should return different result at each call');
        $this->assertNotEmpty($s1, 'text() should never return empty result');
        $this->assertNotEmpty($s2, 'text() should never return empty result');
        $this->assertNotEmpty(preg_match("/^[a-zA-Z0-9_\\/\\+\\-]+$/", $s1), 'text() should be b64 encoded');

        $s1l = $len - 16; // less then $len, from begining
        $s2l = 13;
        $s3l = 22;
        $s4l = 3*$len;    // buffer + seed more times
        $s1 = self::$inst->text($s1l);
        $s2 = self::$inst->text($s2l);
        $s3 = self::$inst->text($s3l);
        $s4 = self::$inst->text($s4l);

        $this->assertNotEmpty($s1, "text({$s1l}) should never return empty result");
        $this->assertNotEmpty($s2, 'text() should never return empty result');
        $this->assertEquals(strlen($s1), $s1l, "text({$s1l}) returned different length: ".strlen($s1));
        $this->assertEquals(strlen($s2), $s2l, "text({$s2l}) returned different length: ".strlen($s2));
        $this->assertEquals(strlen($s3), $s3l, "text({$s3l}) returned different length: ".strlen($s3));
        $this->assertEquals(strlen($s4), $s4l, "text({$s4l}) returned different length: ".strlen($s4));
    }

    // -----------------------------------------------------
    public function testHex() {
        $s1  = self::$inst->hex();
        $s2  = self::$inst->hex();
        $len = strlen($s2);

        self::log("hex() ->", substr($s2, 0, 48). '...');
        self::log('strlen(hex()) ==', $len);

        $this->assertNotEquals($s1, $s2, 'hex() should return different result at each call');
        $this->assertNotEmpty($s1, 'hex() should never return empty result');
        $this->assertNotEmpty($s2, 'hex() should never return empty result');
        $this->assertNotEmpty(preg_match("/^[a-fA-F0-9]+$/", $s1), 'hex() should have only hex digits');

        $s1l = $len - 14; // less then $len, from begining
        $s2l = 11;
        $s3l = 16;
        $s4l = 3*$len;    // buffer + seed more times
        $s1 = self::$inst->hex($s1l);
        $s2 = self::$inst->hex($s2l);
        $s3 = self::$inst->hex($s3l);
        $s4 = self::$inst->hex($s4l);

        $this->assertNotEmpty($s1, "hex({$s1l}) should never return empty result");
        $this->assertNotEmpty($s2, 'hex() should never return empty result');
        $this->assertEquals(strlen($s1), $s1l, "hex({$s1l}) returned different length: ".strlen($s1));
        $this->assertEquals(strlen($s2), $s2l, "hex({$s2l}) returned different length: ".strlen($s2));
        $this->assertEquals(strlen($s3), $s3l, "hex({$s3l}) returned different length: ".strlen($s3));
        $this->assertEquals(strlen($s4), $s4l, "hex({$s4l}) returned different length: ".strlen($s4));
    }

    // -----------------------------------------------------
    public function testStateFile() {
        self::$inst->state();
        $this->assertNotEmpty(self::$inst->state_file, '$state_file is empty');
        self::$inst->saveState();
        $this->assertFileExists(self::$inst->state_file, 'state_file not saved ('.self::$inst->state_file.')');

        self::log(self::$inst->state_file);
    }

    // -----------------------------------------------------
    public function testSeed() {
        $s1   = self::$inst->state();
        $e    = self::$inst->hash($s1 . __FUNCTION__, true);
        $bytes = 64; // for network seeding

        // Uncomment next lines to use P2P seeding:
        // Note: HTTPS is better for security, but it is too slow. Use HTTP for tests.

        // $e = file_get_contents('https://duzun.me/entropy/str/'.self::$inst->bin2text($e));
        // self::log('e', self::$inst->bin2text($e));

        // $e = file_get_contents('https://jsonlib.appspot.com/urandom?bytes='.$bytes);
        // $t = json_decode($e) and $t = $t->urandom and $e = $t;
        // self::log('e', self::$inst->bin2text($e));

        // $e = file_get_contents('http://www.random.org/cgi-bin/randbyte?format=f&nbytes='.$bytes);
        // self::log('e', self::$inst->bin2text($e));

        $seed = self::$inst->seed($e);
        $s2   = self::$inst->state();

        $this->assertNotEquals($s1, $s2, 'seed() didn\'t change the state');
        $this->assertNotEmpty($seed, 'seed() returns empty result');
    }

    // -----------------------------------------------------
    public function testDynEntropy() {
        $o = self::$inst;

        $e1 = $o->dynEntropy();
        $e2 = $o->dynEntropy();
        $this->assertNotEquals($e1, $e2, 'dynEntropy() should return different values');
        $this->assertNotEmpty($e1, 'dynEntropy() should not be empty');
        $this->assertNotEmpty($e2, 'dynEntropy() should not be empty');

        self::log('dynEntropy() ->', $o->bin2text($e1));
        self::log('dynEntropy() ->', $o->bin2text($e2));
    }

    // -----------------------------------------------------
    // -----------------------------------------------------
    static function log() {
        if ( empty(self::$log) ) return;
        static $idx = 0;
        static $lastTest;
        if ( $lastTest != self::$testName ) {
            echo PHP_EOL, '-> ', self::$testName, ' ()';
            $lastTest = self::$testName;
        }
        $args = func_get_args();
        foreach($args as $k => $v) is_string($v) or is_int($v) or is_float($v) or $args[$k] = var_export($v, true);
        echo PHP_EOL
            , ""
            , str_pad(++$idx, 3, ' ', STR_PAD_LEFT)
            , ")\t"
            , implode(' ', $args)
        ;
    }
    // -----------------------------------------------------
    // -----------------------------------------------------

}
?>