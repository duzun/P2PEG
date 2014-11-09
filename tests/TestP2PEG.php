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

    // Before any test
    static public function setUpBeforeClass() {
        self::$inst = new TestP2PEG4Tests('Unit test');
    }

    // After all tests
    static public function tearDownAfterClass() {
        if(!empty(self::$inst->state_file))
            unlink(self::$inst->state_file);

        self::$inst = NULL;
    }


    // Before every test
    public function setUp() {
        self::$inst->seed(__FUNCTION__);
    }

    // After every test
    public function tearDown() {
    }

    // -----------------------------------------------------
    /**
     *  @author DUzun
     */
    public function testClass() {
        $this->assertClassHasStaticAttribute('version' , self::$className);
        $this->assertClassHasStaticAttribute('start_ts', self::$className);
        $this->assertClassHasAttribute('state_file', self::$className);
        $this->assertClassHasAttribute('seedSys'   , self::$className);
    }

    // -----------------------------------------------------
    /**
     *  @author DUzun
     */
    public function testHash() {
        self::$inst->setSecret('secret 1');
        $h1  = self::$inst->hash('test', true);
        $h1r = self::$inst->hash('test', false);

        $this->assertGreaterThan(0, strlen($h1), 'raw hash is empty');
        $this->assertGreaterThan(0, strlen($h1r), 'hash is empty');
        $this->assertRegExp('#[^0-9a-fA-F]#', $h1, "hash('test', true) doen't seem to be raw");
        $this->assertNotRegExp('#[^0-9a-fA-F]#', $h1r, "hash('test', false) is not hex");

        self::$inst->setSecret('secret 2');
        $h2 = self::$inst->hash('test', true);

        $this->assertNotEquals($h1, $h2, 'Secret change did not affect hash()');
    }

    // -----------------------------------------------------
    /**
     *  @author DUzun
     */
    public function testStateFile() {
        self::$inst->state();
        $this->assertNotEmpty(self::$inst->state_file, '$state_file is empty');
        self::$inst->save_state();
        $this->assertFileExists(self::$inst->state_file, 'state_file not saved ('.self::$inst->state_file.')');

        echo PHP_EOL;
        echo '$state_file: ';
        var_export(self::$inst->state_file);
        echo PHP_EOL;
    }

    // -----------------------------------------------------
    /**
     *  @author DUzun
     */
    public function testSeed() {
        $s1 = self::$inst->state();
        $seed = self::$inst->seed(__FUNCTION__);
        $s2 = self::$inst->state();

        $this->assertNotEquals($s1, $s2, 'seed() didn\'t change the state');
        $this->assertNotEmpty($seed, 'seed() returns empty result');
    }


    // -----------------------------------------------------
    /**
     *  @author DUzun
     */
    public function testStr() {
        $s1  = self::$inst->str();
        $len = strlen($s1);
        $s2  = self::$inst->str();

        $this->assertNotEquals($s1, $s2, 'str() should return different result at each call');
        $this->assertNotEmpty($s1, 'str() should never return empty result');
        $this->assertNotEmpty($s2, 'str() should never return empty result');

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
    // -----------------------------------------------------

}
?>