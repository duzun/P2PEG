<?php
/*!
 *  Peer to Peer Entropy Generator
 *  or Random numbers generator with p2p seeding
 *
 *  This class uses a combination of system data, client supplied data,
 *  some PRNGs available to PHP and timing to generate unpredictable
 *  entropy data.
 *  *
 *  Each pear adds to the entropy, by suppling variable data with the request (in purpos or not)
 *  and by the fact of connecting to the server (the exact request time is also accounted).
 *  *
 *  For connecting pears there is no way to know about internal server state.
 *  *
 *  For anyone trying to compute the state of the entropy data at a given point in time,
 *  or trying to guess
 *
 *  @TODO
 *
 *  1.  To improve the entropy unpredictability, I intend to create system
 *      where multiple machines periodically exchange entropy.
 *      Each pear gets entropy and gives entropy at the same time
 *      with a simple GET request like this one:
 *
 *      curl https://DUzun.Me/entropy/<hash(random_func().$secret)>
 *
 *
 *  2.  Seed /dev/random and update entropy count, to improve system performance
 *
 *
 *  3.  Count the amount of entropy generated
 *
 *
 *  @version 0.6.6
 *  @author Dumitru Uzun (DUzun.Me)
 *
 */

define('P2PEG_INT16_MASK', -1 << 16 ^ -1);
define('P2PEG_INT32_MASK', -1 << 32 ^ -1);
define('P2PEG_SIGN_BIT', -1<<(PHP_INT_SIZE<<3)-1);

class P2PEG {
    public static $version = '0.6.6';

    // First start timestamp
    public static $start_ts;

    // Singleton instance
    protected static $instance;

    /// Path to a file where to store state data
    public $state_file;

    public $debug = false;

    /// Use first available hash alg from the list
    public $hash = array('sha512', 'sha256', 'sha128', 'sha1', 'md5', 'ripemd128', 'ripemd160');

    // Padding for HMAC-HASH
    private $_opad, $_ipad;

    // If true, call seedRandomDev() on __destruct
    public $seedSys = true;

    // Seed for rand32(), rand64() and other PRNGs
    public $rs = array();

    // State values
    private   $_state;
    protected $_state_mtime;
    protected $_clientEntropy;
    protected $_serverEntropy;
    protected $_serverEEntropy;
    protected $_filesystemEntropy;

    // internal buffer
    private $_b = ''; // data
    private $_l = 0;  // available (unused) length

    // How many degimal digits fit in one int
    protected static $int_len;
    // -------------------------------------------------
    /// Get the singleton instance
    public static function instance($secret=NULL) {
        if(!isset(self::$instance)) {
            self::$instance = new self($secret);
        }
        return self::$instance;
    }
    // -------------------------------------------------
    /// @param (string)$secret - A secred string, should be unique on each installation (: http://xkcd.com/221/ :)
    public function __construct($secret=NULL) {
        // parent::__construct();
        isset(self::$start_ts) or self::$start_ts = microtime(true);
        isset(self::$int_len) or self::$int_len = round(PHP_INT_SIZE * log10(256));
        $this->seedSys = !$this->isWindows();

        // No secred key? Generate one!
        if ( !isset($secret) ) {
            $secret = $this->packFloat(self::$start_ts) . 'H{tCAD;](WS[v|\\0}0cgd/(*;1NUd_5trdB:Qmn8s5%,FK*Civ(&' . self::$version;
        }
        $this->setSecret($secret);
    }

    public function __destruct() {
        // parent::__destruct();

        // Save state to a file
        $this->saveState();

        // Influence /dev/urandom and /dev/random
        if($this->seedSys) $this->seedRandomDev(__METHOD__);
    }
    // -------------------------------------------------
    public function saveState($sf=NULL) {
        if(!$this->_state) return false; // Nothing to save
        if(!$sf) $sf = $this->state_file;
        if(!$sf) return false; // No where to save

        static $oldPHP;
        isset($oldPHP) or $oldPHP = version_compare(PHP_VERSION, '5.3.0') < 0;
        // If meanwhile state file changed, don't loose that entropy
        $oldPHP ? clearstatcache() : clearstatcache(true, $sf);

        $flags = 1;
        if(@filemtime($sf) != $this->_state_mtime) {
            $flags |= FILE_APPEND;
        }
        // @TODO: Watch for state_file size if the server is very busy

        return @$this->flock_put_contents($sf, $this->_state, $flags);
    }
    // -------------------------------------------------
    public function warmup($secret=NULL) {
        isset($secret) and $this->setSecret($secret);
        $this->state();
        // $this->serverEntropy();
        // $this->clientEntropy();
    }

    // -------------------------------------------------
    /**
     *  Seed P2PEG with some entropy.
     */
    public function seed($seed=NULL) {
        $ret = $this->state()
               . $seed
               . $this->dynEntropy()
        ;
        $ret = $this->hash($ret);
        $this->_state ^= $ret;
        $this->_b = $ret;
        $this->_l = strlen($ret);
        return $ret;
    }

    // -------------------------------------------------
    /**
     *  Return a random binary string of specified length.
     */
    public function str($len=NULL) {
        // If buffer is empty, fill it
        if(!($l = $this->_l)) {
            $this->seed($len);
            $l = $this->_l;
        }
        // If we have to return exactly what is in the buffer, return quickly
        if(!isset($len) || $len == $l) {
            // remove used data from buffer to avoid reusing it
            $ret = $l < strlen($this->_b) ? substr($this->_b, 0, $l) : $this->_b;
            // empty the buffer
            $this->_b = '';
            $this->_l = 0;
            return $ret;
        }

        $ret = '';
        // If we need more data than we have in the buffer, generate some more
        if($l < $len) {
            // remove used data from buffer to avoid reusing it
            if($l < strlen($this->_b)) $this->_b = substr($this->_b, 0, $l);

            do {
                $ret .= $this->_b; // save what is in the buffer
                $this->seed($l);   // fill it again
                $l += $this->_l;   // the sum of what we have saved in $ret and what is in the buffer
            } while($l < $len);
        }

        // If buffer has more data then we need
        if($len < $l) {
            // how much data we don't need from buffer ?
            $this->_l = $l - $len;
            // get only that much we need from buffer and leave the rest for others
            $ret .= substr($this->_b, $this->_l, $len);
        }
        // else buffer has exactly how much data we need - grab it all
        else {
            $ret .= $this->_b;
            // empty the buffer
            $this->_b = '';
            $this->_l = 0;
        }
        return $ret;
    }


    /**
     *  Hex encoded string
     */
    public function hex($len=NULL) {
        $l = isset($len) ? ($len+1) >> 1 : $len;
        $ret = $this->str($l);
        $ret = bin2hex($ret);
        return !isset($len) || strlen($ret) == $len
            ? $ret
            : substr($ret, 0, $len)
        ;
    }

    /**
     * Base64 encoded text (for URL) or text based on the supplied alphabet
     *
     * @param  int    $len      Length of the generated text
     * @param  string $alphabet Pattern or just a string - OPTIONAL. If missing, base64 encoded
     * @return string
     */
    public function text($len=NULL, $alphabet=NULL) {
        if ( !empty($alphabet) ) return $this->alpha($alphabet, $len);

        $l = isset($len) ? ceil((float)$len * 3.0 / 4.0) : NULL;
        $ret = $this->bin2text($this->str($l));
        if(isset($len) && strlen($ret) > $len) $ret = substr($ret, 0, $len);
        return $ret;
    }

    /**
     * Generate text with a given alphabet.
     *
     * @param  string $alphabet Pattern or just a string
     * @param  int    $len      Length of the generated string
     * @return string
     */
    public function alpha($alphabet, $len=NULL) {
        $alphabet = self::expand_alpha($alphabet);
        $alpha_len = strlen($alphabet);
        $bit_size = ceil(log($alpha_len, 2));
        $s = $this->str(isset($len) ? ceil((float)$len * $bit_size / 8) : NULL);
        $l = strlen($s);
        $r = '';
        $b = 0;
        $c = 0;
        $m = -1 << $bit_size ^ -1;
        for($i=0; $i<$l; $i++) {
            $b = ($b << 8) | ord(substr($s, $i, 1));
            $c += 8;
            while($c >= $bit_size) {
                if ( isset($len) && strlen($r) >= $len ) break 2;
                $r .= $alphabet[($b & $m) % $alpha_len];
                $c -= $bit_size;
                $b >>= $bit_size;
            }
        }

        return $r;
    }

    /**
     * Expand alphanumeric paterns
     *
     * @param  string $a First char of the expansion or a patern like "a-z0-9_!"
     * @param  string $z Last char or the expansion
     * @return string A string of all letter between $a and $z (including) or the expanded pattern of $a
     */
    public static function expand_alpha($a, $z=NULL) {
        if ( !isset($z) ) {
            $i = 1;
            $l = strlen($a);
            $r = '';
            while( $i < $l and $p = strpos($a, '-', $i) and $p+1 < $l ) {
                $z = self::expand_alpha(substr($a, $p-1), substr($a, $p+1));
                $a = substr($a, 0, $p-1) . $z . substr($a, $p+2);
                $l += strlen($z) - 3;
                $i = $p + strlen($z);
            }

            return $a;
        }

        $b = ord($a);
        $e = ord($z);
        if ( $b > $e ) {
            $t = $b; $b = $e; $e = $t;
        }
        $ret = array();
        for(; $b <= $e; $b++) {
            $ret[] = chr($b);
        }

        return implode('', $ret);
    }


    /**
     *  Return a random 16 bit integer.
     *
     *  @return (int)random
     */
    public function int16() {
        $r = unpack('s', $this->str(2));
        return reset($r);
    }

    /**
     *  Return a random 32 bit integer.
     *
     *  @return (int)random
     */
    public function int32() {
        $r = unpack('l', $this->str(4));
        return reset($r);
    }

    /**
     *  Return a random integer.
     *
     *  @param (int)$size - number of bytes used to generate the integer [1..PHP_INT_SIZE].
     *                      Defaults to PHP_INT_SIZE (4 or 8, depending on system)
     *      Ex. If $size == 1, the result is a number from interval [0..255].
     *          If $size == 3, the result is a number from interval [0..16777215].
     *
     *  @return (int)random
     *
     */
    public function int($size=NULL) {
        $s = isset($size) ? $size : PHP_INT_SIZE;
        $src = $this->str($s);
        $r = 0;
        for(;$s--;) $r = ($r << 8) | ord(substr($src, $s, 1));
        return $r;
    }

    // -------------------------------------------------
    /**
     * Equivalent of PHP's rand(), only using our entropy.
     *
     * @param  int    $min The lowest value to return (default: 0)
     * @param  int    $max The highest value to return (default: PHP_INT_MAX)
     * @param  string $algo Name of a P2PEG method that returns an integer
     * @param  int    $max_size The highest value $this->$algo() could return
     * @return int    An integer between [$min..$max]
     */
    public function rand($min=0, $max=NULL, $algo="int", $max_size=PHP_INT_MAX, $arg=NULL) {
        isset($max) or $max = $max_size;
        $num = $this->$algo($arg);
        // if ( abs($num) > $max_size ) {
        //     $num &= $max_size; // not 100% correct, but in some cases might help
        // }
        return $min + ((1 + $num / ($max_size + 1)) * ($max - $min + 1) >> 1);
    }

    // -------------------------------------------------
    /**
     * How many bytes are required to represent this integer?
     *
     * @param  int $int An integer
     * @return int Number of not 0 bytes of $int
     */
    public static function sizeOfInt($int) {
        $m = -1 << ((PHP_INT_SIZE-1)<<3);
        $c = PHP_INT_SIZE;
        while(!($b = $int & $m) || $b == 0xFF and $c) {
            --$c;
            $m >>= 8;
        }
        return $c;
    }

/* --- PRNGs ---------------------------------------------------------------- */

    public function _init_rs32($len) {
        $count = count($this->rs);
        while($count < $len) $this->rs[$count++] = $this->int32();
        return $this->rs;
    }

    public function _init_rs($len) {
        $count = count($this->rs);
        while($count < $len) $this->rs[$count++] = $this->int();
        return $this->rs;
    }

    // -------------------------------------------------
    /**
     *  Pseudo-random 32bit integer numbers generator.
     *
     *  This algorithm is a linear congruential pseudo-random number generator.
     *
     *  This function produces same result as $this->int32(),
     *  but is much faster at generating long strings of random numbers,
     *  and uses less entropy as well.
     *
     *  @source http://en.wikipedia.org/wiki/Random_number_generation
     *
     *  @return  (int)random
     */
    public function rand32($strict=true) {
        $rs00 = @$this->rs[0];
        $rs10 = @$this->rs[1];

        // Seed if necessary
        while(!$rs10 || $rs10 == 0x464fffff) {
            /* must not be zero, nor 0x464fffff */
            $rs10 = $this->int32() ^ $this->int32();
        }
        while(!$rs00 || $rs00 == 0x9068ffff) {
            /* must not be zero, nor 0x9068ffff */
            $rs00 = $this->int32() ^ $this->int32();
        }

        $rs00 = 0x9069 * ($rs00 & P2PEG_INT16_MASK) + ($rs00 >> 16);
        $rs10 = 0x4650 * ($rs10 & P2PEG_INT16_MASK) + ($rs10 >> 16);
        $ret = ($rs00 << 16) + $rs10;  /* 32-bit result */

        $this->rs[0] = $rs00;
        $this->rs[1] = $rs10;

        $m = $strict ? P2PEG_INT32_MASK : -1;

        // handle overflow:
        // in PHP at overflow (int) -> (float)
        return $ret & $m;
    }

    // -------------------------------------------------
    /**
     *  Pseudo-random 64bit integer numbers generator (xorshift family).
     *
     *  @source  http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf
     *
     *  @return (int)random
     */
    public function rand64() {
        $rs = $this->rs;
        count($rs) < 4 and $rs = $this->_init_rs32(4);

        $s10 = $rs[0];
        $s11 = $rs[1];
        $s00 = $rs[2];
        $s01 = $rs[3];

        $m = P2PEG_INT32_MASK;

        // Seed if necessary
        while(!$s10 || !$s11) {
            $s10 = $this->int32();
            $s11 = $this->int32();
        }
        while(!$s00 || !$s01) {
            $s00 = $this->int32();
            $s01 = $this->int32();
        }

        $rs[0] = $s00;
        $rs[1] = $s01;

        // $s1 ^= $s1 << 23;
        $s11 ^= ($s11 << 23) & $m | ($s10 >> 9);
        $s10 ^= ($s10 << 23) & $m;

        // $s1 ^= $s1 >> 17;
        $s10 ^= ($s11 << 15) & $m | ($s10 >> 17);
        $s11 ^= $s11 >> 17;

        // $s1 ^= $s0;
        $s10 ^= $s00;
        $s11 ^= $s01;

        // $s1 ^= $s0 >> 26;
        $s10 ^= ($s01 << 8) & $m | ($s00 >> 26);
        $s11 ^= $s01 >> 26;

        $rs[2] = $s10;
        $rs[3] = $s11;

        $this->rs = $rs;

        return (($rs[1] + $rs[3]) << 32) | ($rs[0] + $rs[2]);
    }

    /**
     * Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs"
     *
     * @return int32
     */
    public function xorShift32($strict=true) {
        $x = @$this->rs[0];

        // Seed if necessary
        while(!$x) {
            $x = $this->int32();
        }

        $x ^= $x << 13;
        $strict and $x &= P2PEG_INT32_MASK;
        $x ^= $x >> 17;
        $x ^= $x << 5;
        $strict and $x &= P2PEG_INT32_MASK;
        return $this->rs[0] = $x;
    }

    /**
     * Algorithm "xor128" from p. 5 of Marsaglia, "Xorshift RNGs"
     *
     * @return int32
     */
    public function xorShift128($strict=true) {
        count($this->rs) < 4 and $this->_init_rs32(4);

        $t = array_splice($this->rs, 3, 1);
        $s = $this->rs[0];

        $t ^= $t[0] << 11;

        if ( $strict ) {
            $t ^= ($t >> 8) & (-1 << 24 ^ -1);

            $t ^= $s;
            $t ^= ($s >> 19) & (-1 << 13 ^ -1);

            $t &= P2PEG_INT32_MASK;
        }
        else {
            $t ^= $t >> 8;
            $t ^= $s;
            $t ^= $s >> 19;
        }

        array_unshift($this->rs, $t);

        return $t;
    }

    /**
     * Algorithm "xorwow" from p. 5 of Marsaglia, "Xorshift RNGs"
     *
     * @note This generator is the default in Nvidia's CUDA toolkit.
     *
     * @period 2^160−2^32
     *
     * @return int32
     */
    public function xorwow($strict=true) {
        if ( count($this->rs) < 4 ) {
            $this->_init_rs32(4);
        }

        $t = array_splice($this->rs, 3, 1);
        $s = $this->rs[0];

        $m = $strict ? P2PEG_INT32_MASK : -1;

        $t ^= $strict ? (($t[0]&$m) >> 2) & (-1 << 30 ^ -1) : $t[0] >> 2;
        $t ^= $t << 1;

        $t ^= $s;
        $t ^= $s << 4;

        array_unshift($this->rs, $t &= $m);

        if ( $strict ) {
            $this->rs[4] = (@$this->rs[4] + 0x587c5) & $m;
            return ($t + $this->rs[4]) & $m;
        }
        else {
            $this->rs[4] = self::add64(@$this->rs[4], 0x587c5);
            return self::add64($t, $this->rs[4]);
        }
    }

    // -------------------------------------------------
    /**
     * This is a fixed-increment version of Java 8's SplittableRandom generator
     *
     * See http://dx.doi.org/10.1145/2714064.2660195 and
     *     http://docs.oracle.com/javase/8/docs/api/java/util/SplittableRandom.html
     *
     * passes BigCrush
     *
     * @return int64
     */
    public function splitMix64() {
        list($z) = $this->_init_rs(1);

        $this->rs[0] =
        $z = self::add64($z, 0x9E3779B97F4A7C15);
        $z ^= ($z >> 30) & (-1 << 34 ^ -1);
        $z = self::mul64($z, 0xBF58476D1CE4E5B9);

        $z ^= ($z >> 27) & (-1 << 37 ^ -1);
        $z = self::mul64($z, 0x94D049BB133111EB);
        return $z ^= ($z >> 31) & (-1 << 33 ^ -1);


        $m = P2PEG_INT32_MASK;

        list($x, $y) = $this->_init_rs32(2);

        $y += 0x7F4A7C15;
        $x += 0x9E3779B9 + (($y >> 32) & $m);

        $x &= $m; $y &= $m;

        $this->rs[0] = $x;
        $this->rs[1] = $y;

        $y ^= (($x << 2) & ~3) | (($y >> 30) & 3);
        $x ^= ($x >> 30) & 3;

        $ah = 0xBF58476D;
        $al = 0x1CE4E5B9;

        $x &= $m; $y &= $m;

        $x = $x * $al + $y * $ah;
        $y = $y * $al;
        $x += ($y >> 32) & $m;

        $y ^= (($x << 5) & ~0x1F) | (($y >> 27) & 0x1F);
        $x ^= ($x >> 27) & 0x1F;

        $ah = 0x94D049BB;
        $al = 0x133111EB;

        $x &= $m; $y &= $m;

        $x = $x * $al + $y * $ah;
        $y = $y * $al;
        $x += ($y >> 32) & $m;

        $y ^= (($x << 1) & ~1) | (($y >> 31) & 1);
        $x ^= ($x >> 31) & 1;

        return ($x << 32) | ($y & $m);
    }

    // -------------------------------------------------
    /**
     * @period 2^1024 − 1
     * passes BigCrush
     *
     * @return int64
     */
    public function xorShift1024Star() {
        static $p = 0;

        $this->_init_rs(16);

        $s0 = $this->rs[$p++];
        $s1 = $this->rs[$p &= 15];

        // There is no UInt64 in PHP, only Int64 on x64 platform, and Int32 on x86,
        // thus, we have to make an unsigned right shift somehow.
        // Main idea is: $x >>> $n === ($x >> $n) & (-1 << (64-$n) ^ -1)
        $s1 ^= $s1 << 31;
        $s1 = $s1 ^ $s0 ^ ($s1 << 31) ^ (($s1 >> 11) & (-1 << 53 ^ -1)) ^ (($s0 >> 30) & 3);

        $this->rs[$p] = $s1;

        // In PHP, we can't just multiply int64 * int64 and get an int64. See mul64()

        return self::mul64($s1, 0x106689D45497FDB5);
        // return ($s1 * 0x106689D45497FDB5); // this is a float in PHP :-(
    }

    /**
     * @period 2^128-1
     *
     * @return int64
     */
    public function xorShift128Plus() {
        list($x, $y) = $this->_init_rs(2);

        $this->rs[0] = $y;

        // There is no UInt64 in PHP, only Int64 on x64 platform, and Int32 on x86,
        // thus, we have to make an unsigned right shift somehow.
        // Main idea is: $x >>> $n === ($x >> $n) & (-1 << (64-$n) ^ -1)
        $x ^= $x << 23;
        $x ^= $y ^ (($x >> 17) & (-1 << 47 ^ -1)) ^ (($y >> 26) & (-1 << 38 ^ -1));
        // $x ^= $y ^ ($x >> 17) ^ ($y >> 26);
        $this->rs[1] = $x;

        return self::add64($x, $y);
        // return ($x + $y); // this is a float in PHP :-(
    }

    // -------------------------------------------------
    /**
     * WARNING! This is a very bad RNG! Here just as an example.
     * See https://www.wikiwand.com/en/RANDU
     *
     * The only good part about this implementation is that the seed is random.
     */
    public function RANDU() {
        $s = $this->_init_rs32(1);
        $s = $s[0];
        // return $this->rs[0] = ($s * 0x10003) & 0x7FFFFFFF;
        return $this->rs[0] = (($s << 16) + ($s << 1) + $s) & 0x7FFFFFFF;
    }

    /**
     * RANDU Deskewed a little bit, but still...
     */
    public function RANDU_Deskewed() {
        return $this->Deskew_uniform_distribution('RANDU');
    }

    // -------------------------------------------------
    /**
     * De-sckew method to nomalize distribution of 0s and 1s.
     *
     * @param string $method A P2PEG method that produces (pseudo) random data
     * @return int|string same type as $method
     */
    public function Deskew_uniform_distribution($method) {
        $g = $this->call($method);

        if ( $g === false ) return $g;

        if ( is_int($g) ) {
            $r = 0;
            for($b = $c = self::sizeOfInt($g) << 3; $c; $g = $this->call($method)) {
                for($i=$b >> 1; $i-- && $c; ) {
                    $x = $g & 3;
                    $g >>= 2;
                    switch($x) {
                        case 1: // 0
                            $r <<= 1;
                            --$c;
                        break;

                        case 2: // 1
                            $r <<= 1;
                            $r |= 1;
                            --$c;
                        break;
                    }
                }
            }
            return $r;
        }
        else {
            $s = '';
            $b = strlen($g);
            for($c = $b << 3, $r = 0; $c; $g = $this->call($method), $b = strlen($g)) {
                for($l=0; $l < $b && $c; $l++) {
                    $f = ord(substr($g, $l, 1));
                    for($i=4; $i-- && $c; ) {
                        $x = $f & 3;
                        $f >>= 2;
                        switch($x) {
                            case 2: // 1
                                $r |= 1;
                            case 1: // 0
                                --$c;
                                if ( ($c & 7) == 0 ) {
                                    $s .= chr($r);
                                    $r = 0;
                                }
                                $r <<= 1;
                            break;
                        }
                    }
                }
            }
            return $s;
        }
    }

    // -------------------------------------------------
    /**
     *  Generate and serve to client a random bitmap image.
     *
     *  This method helps to visually inspect a random number generator (RNG).
     *  It is not enough to know how good the RNG is,
     *  but if you see any pattern, the RNG is bad or something is wrong.
     *
     *  @param (int)$width of the image
     *  @param (int)$height of the image
     *  @param (str)$meth - a method of this class to generate data
     *  @param (int)$wordSize in bits - size of each number or char generated by $meth.
     *                        Defaults to 8 for string and min 32 for int (autodetect from first sample).
     *
     *  @note Requires the GD Library
     *
     *  Inspired by  https://boallen.com/random-numbers.html
     *
     */
    public function servImg($width=64, $height=64, $meth='rand32', $wordSize=NULL, $bitMix=false) {
        $totalSize = $width * $height;

        $g = NULL;

        if ( is_array($bitMix) ) {
            $g = $bitMix;
            $bitMix = false;
        }
        elseif( is_string($bitMix) ) {
            $g = $bitMix;
            $bitMix = true;
        }

        if ( isset($g) ) {
            is_array($meth) or $meth = array($meth);
        }
        else {
            is_array($meth) and count($meth) == 1 and $meth = reset($meth);
        }

        if ( !is_array($meth) ) {
            $m = is_int($meth) || is_numeric($meth) || strncmp($meth, '0', 1) == 0 ? $meth : array($this, $meth);
            $g = self::callable2string($m, $totalSize, $wordSize, false);
            if ( $g === false ) return $g;
        }
        else {
            foreach($meth as $m) {
                $c = is_int($m) || is_numeric($m) || strncmp($m, '0', 1) == 0 ? $m : array($this, $m);
                // 0 is a special method which just enables $bitMix
                if ( $c === 0 || $c === '0' ) {
                    $r = '';
                    $c = 0;
                }
                else {
                    $r = self::callable2string($c, $totalSize, $wordSize, $bitMix);
                    if ( $r === false ) return $r;
                }

                // As long as there are only arrays of items, mix at item/word level,
                if ( !$bitMix ) {
                    // but with first string, make everything string and mix at bit level.
                    if ( is_string($r) ) {
                        $bitMix = true;
                        if ( is_array($g) ) {
                            $g = self::arrayOfInt2String($g, $wordSize ? $wordSize >> 3 : $wordSize);
                        }
                    }
                }

                if ( $c !== 0 ) {
                    $g = self::mixor($g, $r, $wordSize ? $wordSize >> 3 : $wordSize);
                }
            }
            unset($r); // free mem

            // Because we have converted everything to char string, max wordSize is 8
            if ( $bitMix ) {
                $wordSize = min($wordSize, 8);
            }
        }

        header('X-Rand-Meth: ' . implode(', ', (array)$meth));
        self::servStringImg($g, $wordSize, $width, $height);
    }

    // -------------------------------------------------
    public function servImgDyn($width=64, $height=64, $meth='rand32', $wordSize=NULL) {
        $g = $this->call($meth);
        $samples = 1;

        if ( $g === false ) {
            trigger_error(__METHOD__ . ': Wrong method called. '.implode(', ', (array)$meth));
            echo 'Error';
            return false;
        }

        header("Content-type: image/png");
        $im = imagecreatetruecolor($width, $height) or die("Cannot Initialize new GD image stream");
        $white = imagecolorallocate($im, 255, 255, 255);

        $iss = is_string($g); // string or int32
        if($iss) {
            $p = strlen($g);
            $r = ord(substr($g, --$p, 1));
            $bitSize = empty($wordSize) ? 8 : $wordSize; // 1 bytes == 8 bits
        }
        else {
            $r = $g;
            $bitSize = empty($wordSize) ? max(32, self::sizeOfInt($g) << 3) : $wordSize; // 4 bytes == 32 bits
        }
        $i = $bitSize;
        header('X-Rand-Meth: ' . implode(', ', (array)$meth));
        header('X-Word-Size: ' . $bitSize);

        for($y = 0; $y < $height; $y++) {
            for($x = 0; $x < $width; $x++) {
                if($i == 0) {
                    if($iss) {
                        if(!$p) {
                            $g = $this->call($meth);
                            $p = strlen($g);
                            ++$samples;
                        }
                        $r = ord(substr($g, --$p, 1));
                    }
                    else {
                        $r = $this->call($meth);
                        ++$samples;
                    }
                    $i = $bitSize;
                }
                if($r & 1) {
                    imagesetpixel($im, $x, $y, $white);
                }
                $r >>= 1;
                // sign bit should be 0 after first shift
                if ( $r < 0 ) {
                    $r ^= P2PEG_SIGN_BIT;
                }
                --$i;
            }
        }
        header('X-Samples: ' . $samples);
        imagepng($im);
        imagedestroy($im);
    }

    public static function servStringImg($str, $wordSize=NULL, $width=NULL, $height=NULL) {
        $im = self::string2bitImg($str, $wordSize, $width, $height);

        header("Content-type: image/png");
        header('X-Word-Size: ' . $im['bitSize']);
        header('X-Img-Size: ' . $im['width'] . 'x' . $im['height']);
        header('X-Count: ' . (is_string($str) ? strlen($str) : count($str)));
        imagepng($im['img']);
        imagedestroy($im['img']);

        return $im;
    }

    // -------------------------------------------------
    /**
     * Obtain a string of words/chars for a given $callable, with the size $totalBitSize.
     *
     * @param  callable|number $callable A callable that produces int of string.
     *                                   If this is a number (0xHEC, 0b10, 1052 etc),
     *                                   then it is considered as $callable's return
     * @param  int  $totalBitSize The desired length of the resulting string in bits
     * @param  int  $wordSize     Number of bits to take from each word. OPTIONAL
     * @param  boolean $returnString If true, convert the result to string of char
     * @return string|array Depending on $returnString and $callable's output
     */
    public static function callable2string($callable, $totalBitSize, $wordSize=NULL, $returnString=true) {
        if ( is_int($g = self::text2int($callable)) ) {
            $bitSize = empty($wordSize) ? self::sizeOfInt($g) : $wordSize; // 1 bytes == 8 bits
            $g = array_fill(0, ceil($totalBitSize / $bitSize), $g);
        }
        else {
            if ( is_array($callable) && count($callable) > 2 ) {
                $args = array_slice($callable, 2);
                $callable = array_slice($callable, 0, 2);
            }
            else {
                $args = array();
            }
            $g = call_user_func_array($callable, $args);

            if( is_string($g) ) {
                $bitSize = empty($wordSize) ? 8 : $wordSize; // 1 bytes == 8 bits
                $p = strlen($g);
                while(strlen($g) * $bitSize < $totalBitSize) {
                    $g .= call_user_func_array($callable, $args);
                }
            }
            elseif( is_int($g) ) {
                if ( empty($wordSize) ) {
                    $bitSize = self::sizeOfInt($g) << 3;
                }
                else {
                    $bitSize = $wordSize; // 4 bytes == 32 bits
                }
                $g = array($g);
                $v = 0;
                while(count($g) * $bitSize < $totalBitSize) {
                    $g[] = $r = call_user_func_array($callable, $args);
                    if ( empty($wordSize) ) {
                        $i = self::sizeOfInt($r);
                        $b = $i << 3;
                        if ( $b > $bitSize ) {
                            $bitSize = $b;
                            $v = 0;
                            if ( $i == PHP_INT_SIZE ) {
                                $wordSize = $bitSize;
                            }
                        }
                        elseif ( ++$v > 16 ) {
                            $wordSize = $bitSize;
                        }
                    }
                }
            }
            else {
                 // RNGs of this class return either string, or int
                trigger_error(__METHOD__ . ': Wrong callable return. '.(is_string($callable) ? $callable : ''));
                return $g;
            }
        }

        if ( $returnString && is_array($g) ) {
            $g = self::arrayOfInt2String($g, $bitSize >> 3);
        }

        return $g;
    }

    /**
     * Create an image object for a string or words/chars.
     *
     * @param  string|array $str A string or an array of int
     * @param  int  $wordSize   Number of bits to take from each word. OPTIONAL
     * @param  int $width    Image width. OPTIONAL
     * @param  int $height   Image height. OPTIONAL
     * @return array [img, width, height, bitSize]
     */
    public static function string2bitImg($str, $wordSize=NULL, $width=NULL, $height=NULL) {

        if ( $str === false ) {
            trigger_error(__METHOD__ . ': Wrong data supplied.');
            echo __METHOD__ . 'Error';
            return false;
        }

        $iss = is_string($str); // string or [int32]
        if($iss) {
            $p = strlen($str);
            $bitSize = empty($wordSize) ? 8 : $wordSize; // 1 bytes == 8 bits
        }
        else {
            $p = count($str);
            if ( empty($wordSize) ) {
                $bitSize = 0;
                $v = 0;
                foreach($str as $g) {
                    $i = self::sizeOfInt($g);
                    if ( $i > $bitSize ) {
                        $bitSize = $i;
                        if ( $i == PHP_INT_SIZE ) break;
                        $v = 0;
                    }
                    else {
                        if ( ++$v > 16 ) break;
                    }
                }
                $bitSize <<= 3; // convert bytes to bits
            }
            else {
                $bitSize = $wordSize;
            }
        }

        if ( !isset($width) ) {
            $width = round(sqrt($bitSize * $p));
        }
        if ( !isset($height) ) {
            $height = $width;
        }

        $im = imagecreatetruecolor($width, $height) or die("Cannot Initialize new GD image stream");
        $white = imagecolorallocate($im, 255, 255, 255);

        for($y = 0, $i = 0; $y < $height && $p; $y++) {
            for($x = 0; $x < $width && $p; $x++) {
                if($i == 0) {
                    if($iss) {
                        $r = ord(substr($str, --$p, 1));
                    }
                    else {
                        $r = $str[--$p];
                    }
                    $i = $bitSize;
                }
                if($r & 1) {
                    imagesetpixel($im, $x, $y, $white);
                }
                $r >>= 1;
                // sign bit should be 0 after first shift
                if ( $r < 0 ) {
                    $r ^= P2PEG_SIGN_BIT;
                }
                --$i;
            }
        }

        return array('img' => $im, 'width' => $width, 'height' => $height, 'bitSize' => $bitSize);
    }

    // -------------------------------------------------
    public function call($meth) {
        // @TODO: Check if $method is safe to display to client
        if ( is_array($meth) ) {
            $g = NULL;
            foreach($meth as $m) {
                if ( is_int($m) || is_numeric($m) ) {
                    $h = $m;
                }
                // elseif ( !strncmp($m, '\\', 1) && strpos($m, '\\', 1) ) {
                //     $h = $m();
                // }
                else {
                    $h = $this->$m();
                }
                if( is_int($h) ) {
                    if ( is_string($g) ) {
                        $g = self::strxor($g, $this->packInt($h));
                    }
                    else {
                        $g ^= $h;
                    }
                }
                elseif ( is_string($h) ) {
                    if ( !isset($g) ) {
                        $g = $h;
                    }
                    else {
                        if ( is_int($g) ) {
                            $g = $this->packInt($g);
                        }
                        $g = self::strxor($g, $h);
                    }
                }
                else {
                    // RNGs of this class return either string, or int
                    return false;
                }
            }
        }
        else {
            if ( is_int($meth) || is_numeric($meth) ) {
                $g = (int)$meth;
            }
            // elseif ( !strncmp($meth, '\\', 1) && strpos($meth, '\\', 1) ) {
            //     $g = $meth();
            // }
            else {
                $g = $this->$meth();
            }
            // if ( is_float($g) ) $g |= 0;
            if ( !is_int($g) && !is_string($g) ) {
                // RNGs of this class return either string, or int
                return false;
            }
        }

        return $g;
    }
    // -------------------------------------------------
    /**
     * Set internal seecret, used for HMAC-HASH in mixing entropy.
     *
     * @param string|array $key a string or an array of int
     */
    public function setSecret($key) {
        $size = 64;
        if ( is_array($key) ) {
            $key = self::arrayOfInt2String($key);
        }
        $l = strlen($key);
        if($size < $l) {
            $this->_opad = $this->_ipad = NULL;
            $key = $this->hash($key);
            if($key === FALSE) return $key;
            $l = strlen($key);
        }
        if($l < $size) {
            $key = str_pad($key, $size, chr(0));
        }
        else {
            $key = substr($key, 0, -1) . chr(0);
        }

        $this->_opad = str_repeat(chr(0x5C), $size) ^ $key;
        $this->_ipad = str_repeat(chr(0x36), $size) ^ $key;

        // Empty the buffer
        $this->_l = 0;
    }
    // -------------------------------------------------
    /**
     *   Quickly get some dynamic entropy.
     */
    public function dynEntropy($quick=true) {
        $_entr = array();

        $_entr[$this->packInt(+substr(microtime(), 2, 6))] = 'microtime';
        $_entr[$this->packInt(rand())] = 'rand'; // In 7.1.0 rand() has been made an alias of mt_rand()

        // Get some data from mt_rand()
        $r = array();
        $l = rand(1,8);
        for ($i = 0; $i < $l; ++$i) $r[] = pack('S', mt_rand(0, P2PEG_INT16_MASK));
        $r = implode('', $r);
        $_entr[$r] = 'mt_rand';

        // System performance/load indicator
        $r = (microtime(true)-self::$start_ts)*1000;
        $_entr[$this->packFloat($r)] = 'delta';

        $_entr = implode("\x5C", array_keys($_entr));
        return $_entr;
    }

    // -------------------------------------------------
    /*
     * Each connecting client brings in some entropy and influences internal state.
     *
     */
    public function clientEntropy() {
        if(!isset($this->_clientEntropy)) {
            if(strncmp(php_sapi_name(), 'cli', 3) == 0) {
                global $argv;
                $_entr = implode("\x35", $argv);
                $_entr = $_entr ? $this->hash($_entr,true) : '';
                $this->_clientEntropy = $_entr;
                return $_entr;
            }

            $_entr = array();
            foreach(array(
                'REQUEST_URI',
                'HTTP_COOKIE',
                'HTTP_ACCEPT_LANGUAGE',
                'HTTP_ACCEPT',
                'HTTP_USER_AGENT',
                'HTTP_CACHE_CONTROL',
            ) as $t) {
                $r = $this->env($t) and
                $_entr[$r] = $t;
            }
            if(empty($_COOKIE[session_name()]) and $r = session_id()) $_entr[$r] = 'sesid'; // If session just initialized, there is no session id in cookie

            // HTTP_COOKIE and REQUEST_URI might contain private data - hash/hide it at this point
            $_entr = implode("\x5D", array_keys($_entr));
            $_entr = array($this->hash($_entr,true)=>'HTTP');

            foreach(array(
                'REMOTE_ADDR',
                'HTTP_CLIENT_IP', // client might be behind proxy
                'HTTP_X_FORWARDED_FOR',
                'SERVER_ADDR', // server might have more IPv4 addresses - connecting to one of two ADDR is a bit of entropy
            ) as $t) {
                $r = $this->env($t) and
                $_entr[$this->packIP4($r)] = $t;
            }
            $r = ($this->env('REMOTE_PORT')+1)*($this->env('SERVER_PORT')+1);
            $_entr[$this->packInt($r)] = 'port*port';

            if($r = $this->env('REQUEST_TIME_FLOAT')) {
                $_entr[$this->packFloat($r)] = 'rtf';
            }
            else
            if($r = $this->env('REQUEST_TIME')) {
                $_entr[$this->packInt(+$r)] = 'rt';
            }

            $_entr = implode("\x36", array_keys($_entr));
            $this->_clientEntropy = $_entr;
        }
        return $this->_clientEntropy;
    }

    // -------------------------------------------------
    /*
     * Entropy private to server
     */
    public function serverEntropy() {
        if(!isset($this->_serverEntropy)) {
            $_entr = array();
            $_entr[php_uname('s')] = 's'; // 'Linux' - less useful, cause it never changes
            $_entr[php_uname('r')] = 'r';
            $_entr[php_uname('v')] = 'v';
            $_entr[phpversion()] = 'php';
            $_entr[php_sapi_name()] = 'sapi';
            $_entr[$this->packIP4(self::$version)] = 'ver';

            $t = getmypid()   and $_entr[$this->packInt($t)] = 'pid';
            $t = getmyuid()   and $_entr[$this->packInt($t)] = 'uid';
            $t = getlastmod() and $_entr[$this->packInt($t)] = 'lastmod';

            if(function_exists('openssl_random_pseudo_bytes')) {
                $t = openssl_random_pseudo_bytes(32) and
                $_entr[$t] = 1;
            }

            if(function_exists('random_bytes')) {
                $t = random_bytes(32) and
                $_entr[$t] = 'random_bytes';
            }
            else
            // mcrypt_create_iv() is Deprecated in PHP7.1 and replaced by random_bytes()
            if(
                function_exists('mcrypt_create_iv') && (
                    // Windows on PHP < 5.3.7 is broken, but non-Windows is not known to be.
                    DIRECTORY_SEPARATOR === '/' || @PHP_VERSION_ID >= 50307
                ) && (
                    // Prevent this code from hanging indefinitely on non-Windows;
                    // see https://bugs.php.net/bug.php?id=69833
                    DIRECTORY_SEPARATOR !== '/' ||
                    !defined('PHP_VERSION_ID') || // This constant was introduced in PHP 5.2.7
                    (PHP_VERSION_ID <= 50609 || PHP_VERSION_ID >= 50613)
                )
            ) {
                $t = mcrypt_create_iv(32) and
                $_entr[$t] = 'mcrypt_create_iv';
            }

            $_entr[$this->packFloat(self::$start_ts)] = 'start';

            $_entr = implode("\x5B", array_keys($_entr));
            $this->_serverEntropy = $_entr;
        }
        return $this->_serverEntropy;
    }

    // -------------------------------------------------
    public function filesystemEntropy($dirs=NULL, $maxRead=0) {
        if(!isset($dirs)) {
            if(isset($this->_filesystemEntropy)) return $this->_filesystemEntropy;
            // $_save_result = true;
            $dirs = array(session_save_path(), sys_get_temp_dir(), $this->env('DOCUMENT_ROOT'));
        }
        if(!$maxRead) {
            $maxRead = mt_rand(100,500);
        }
        if(!$dirs) return false;

        if(!is_array($dirs)) $dirs = array($dirs);

        // Unique
        $dirs = array_flip($dirs);

        $buf = '';
        foreach($dirs as $dir => $v) if($d = @opendir($dir)) {
            $h = self::strxor((($v+1)*$maxRead) . $d . $this->packInt(filemtime($dir)), $dir);
            $i = $maxRead;
            while($i-- > 0 and $f = readdir($d)) if($f != '.' && $f != '..') {
                $h = self::strxor($h, $f);
            }
            $buf .= $h;
            closedir($d);
        }
        $this->_filesystemEntropy = $buf;
        return $buf;
    }

    // -------------------------------------------------
    /**
     *  Server Expensive entropy.
     *
     *  Note: Contains serverEntropy()
     *
     */
    public function serverEEntropy($autoseed=true) {
        if(!isset($this->_serverEEntropy)) {
            $_entr = array();
            $len = 64;

            $is_win = $this->isWindows();

            $cmds = $is_win
                ? array('net stats srv')
                : array('uptime', 'iostat', 'ps');

            // Some system data
            foreach ($cmds as $cmd) {
                $s = array();
                @exec($cmd, $s, $ret);
                if($s && is_array($s) && $ret === 0) {
                    foreach($s as $v) {
                        if(false !== preg_match_all('/[1-9]+/', $v, $m) && !empty($m[0])) {
                            $m = implode('', $m[0]);
                            $_entr[$this->packInt($m)] = $cmd;
                        }
                    }
                }
            }

            // /dev/random
            if( false !== ($f = @fopen('/dev/random', 'r')) ) {
                stream_set_blocking($f, 0);
                if(false !== ($r = @fread($f, $len))) {
                    $_entr[$r] = '/dev/random';
                }
                fclose($f);
            }

            if($r = $this->filesystemEntropy()) {
                $_entr[$r] = 'fs';
            }

            $_entr = implode('', array_keys($_entr));

            // Don't waste the chance to seed our P2PEG with some extra entropy
            $autoseed and $this->seed($_entr);

            $_entr .= $this->serverEntropy();

            $this->_serverEEntropy = $_entr;
        }
        return $this->_serverEEntropy;
    }

    // -------------------------------------------------
    public function networkEntropy($autoseed=true) {
        $_entr = array();
        $len = 256;

        $t1 = microtime(true);

        // HTTPS is better for security, but slower.
        $proto = 'https';

        // www.random.org
        if( false !== ($r = @file_get_contents($proto.'://www.random.org/cgi-bin/randbyte?format=f&nbytes=' . $len)) ) {
            $_entr[$r] = 'random.org';
        }
        else
        // jsonlib.appspot.com
        if ( false !== ($r = file_get_contents($proto.'://jsonlib.appspot.com/urandom?bytes='.$len)) ) {
            $t = json_decode($r) and
            $t = $t->urandom and $r = $t;
            $_entr[$r] = 'jsonlib.appspot.com';
        }

        // @TODO: read from other P2PEG servers

        $delta = microtime(true) - $t1;

        $_entr[$this->packFloat($delta)] = 'delta';

        $_entr = implode("\x53", array_keys($_entr));

        // Don't waste the chance to seed our P2PEG with some extra entropy
        $autoseed and $this->seed($_entr);

        return $_entr;
    }

    // -------------------------------------------------
    /**
     *  Since this class is designed to run as quick as posible,
     *  this method is not called by default.
     *  *
     *  You should call this method only in places where speed is not
     *  critical (ex. on cron, in a background request)
     *
     */
    public function expensiveEntropy($autoseed=true) {
        $_entr = '';

        if($r = $this->serverEEntropy(false)) {
            $_entr .= $r;
        }

        if($r = $this->networkEntropy(false)) {
            $_entr .= $r;
        }

        // Don't waste the chance to seed our P2PEG with some extra entropy
        $autoseed and $this->seed($_entr);

        return $_entr;
    }

    // -------------------------------------------------

    public function state() {
        if(!isset($this->_state)) {
            if(!$this->state_file) {
                $this->state_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . __CLASS__ . '.dat';
            }
            $state_file = $this->state_file;
            if($state_file) {
                if(file_exists($state_file)) {
                    // We could use filemtime($state_file) as entropy too
                    $this->_state_mtime = filemtime($state_file);
                    $this->_state = $this->flock_get_contents($state_file);
                }
                else {
                    $this->_state_mtime = 0;
                    is_dir($dir = dirname($state_file)) or mkdir($dir, 0600, true);
                }
            }

            // Seed the state
            $seed = $this->hash($this->clientEntropy() . $this->dynEntropy() . $this->serverEntropy());

            // No state - init it with some initial entropy
            if(!$this->_state) {
                $this->_state = $this->hash(
                    $this->serverEEntropy(false) // could be a bit expensive, but it is run only the first time
                );
            }
            // Update state before next save
            else {
                // Align state value with our hash function
                if(strlen($this->_state) < strlen($seed)) {
                    $this->_state = $this->hash($seed.$this->_state);
                }
            }

            // New state depends on previous state and the entropy of current request
            $this->_state ^= $seed;
        }
        return $this->_state;
    }

    // -------------------------------------------------

    /**
     * Calculate HMAC hash of $str using internal secret.
     *
     * @param  string  $str A message to hash.
     * @param  boolean $raw If true, return raw/binary data. Hex otherwise.
     * @return string  hash or $str
     */
    public function hash($str, $raw=true) {
        $str = $this->_ipad . $str;

        // Look for a supported hash algo from the given list
        if(is_array($this->hash)) {
            foreach($this->hash as $h) {
                $ret = hash($h, $str, true);
                // If $h algo is supported, store it in $this->hash
                // and use it for this and next cycles
                if($ret !== false) {
                    $this->hash = $h;
                    return hash($h, $this->_opad . $ret, $raw);
                }
            }

            // There should exist at least one cryptographic hash algo...
            $this->hash = 'sha1'; // minimum required sha1
        }

        // Apply the hash algo in HMAC fashion in combination with the internal secret key,
        // this way we diminish the effects of eventual poor design of the hash algo.
        $ret = hash($this->hash, $this->_opad . hash($this->hash, $this->_ipad . $str, true), $raw);
        return $ret;
    }
    // -------------------------------------------------

    // Helper methods:

    // -------------------------------------------------
    /**
     * Int64 multiplication in PHP on x64 platform.
     *
     * Explanation:
     *    In PHP, when we multiply two int64 numbers with overflow, we get a float.
     *    In order to multiply int64 * int64 and get the result as int64,
     *    ignoring the overflow, we have to multiply int32 numbers.
     *    a * b = (ah*2^32 + al) * (bh*2^32 + bl) = ah*bh*2^64 + (ah*bl + al*bh)*2^32 + al*bl,
     *    where ah*bh*2^64 is the overflow.
     *
     * @param  int64 $a
     * @param  int64 $b
     * @return int64 $a * $b
     */
    public static function mul64($a, $b) {
        // Split $a and $b into two int32 numbers

        $la = $a & P2PEG_INT32_MASK;
        $ha = ($a >> 32) & P2PEG_INT32_MASK;

        $lb = $b & P2PEG_INT32_MASK;
        $hb = ($b >> 32) & P2PEG_INT32_MASK;

        // Multiply in 2^32
        return ($ha * $lb + $la * $hb + ($la * $lb >> 32) << 32) | ($la * $lb) & P2PEG_INT32_MASK;
    }

    // -------------------------------------------------
    /**
     * Int64 addition in PHP on x64 platform.
     *
     * @param  int64 $a
     * @param  int64 $b
     * @return int64 $a + $b
     */
    public static function add64($x, $y) {
        $x32 = $x & P2PEG_INT32_MASK;
        $y32 = $y & P2PEG_INT32_MASK;
        $xy = $x32 + $y32;
        return ((($x >> 32) + ($y >> 32) + ($xy >> 32)) << 32) | ($xy & P2PEG_INT32_MASK);
    }

    // -------------------------------------------------
    /**
     * Compact an IPv4 string into a binary 4 byte string
     *
     * @param  string $ip IPv4 (eg. 127.0.0.1)
     * @return string
     */
    public function packIP4($ip) {
        $r = '';
        $ip = explode('.', $ip);
        $hasNaN = false;
        foreach($ip as $i) {
            $t = intval($i=trim($i));
            if ( !$t && strncmp($i, '0', 1) ) {
                $hasNaN = true;
                continue;
            }
            $r .= chr($t & 0xFF);
        }
        if ( $hasNaN && !strlen($r) ) return false;
        return $r;
    }

    /**
     * Compact an integer into a string.
     *
     * @param  int $int An integer
     * @return string
     */
    public function packInt($int) {
        $r = '';
        if(is_string($int)) {
            $int = ltrim($int, '0.');
            if(strlen($int) > self::$int_len) {
                $i = str_split($int, self::$int_len);
                foreach($i as $v) $r .= $this->packInt(intval($v));
                return $r;
            }
            $int = +$int;
        }
        // When $int is bigger then int32 (on x86 it is converted to float), shift cuts out some bits.
        // Split the number into 3 pieces of 24 bits ($int is a 53 bit precision double)
        if ( $int > PHP_INT_MAX + 1 ) {
            $m = ~(-1<<((PHP_INT_SIZE-1)<<3));
            return $this->packInt($int & $m) .
                   $this->packInt(($int /= $m+1) & $m) .
                   $this->packInt(($int / ($m+1)) | 0) ;
        }

        $m = $int < 0 ? -1 : 0;
        while($int != $m) {
            $r .= chr($int & 0xFF);
            $int >>= 8;
        }
        return $r;
    }

    /**
     * Compact a float/double intro a binary string.
     *
     * @param  float $float A double
     * @return string
     */
    public function packFloat($float) {
        $t = explode('.', $float, 2);
        return count($t) == 2
            ? $this->packInt($t[1].$t[0]).$this->packInt(strlen($t[1]))
            : $this->packInt($float)
        ;
    }

    // -------------------------------------------------
    /**
     * Convert binary string to base64, suitable for URL.
     *
     * @param  string $bin
     * @return string base64 of $bin
     */
    public function bin2text($bin) {
        $text = strtr(rtrim(base64_encode($bin), '='), '+/', '-_');
        return $text;
    }

    /**
     * Decode a base64 string.
     *
     * @param  string  $text   base64 encoded string
     * @param  boolean $strict If true, be strict about $text
     * @return string decoded (binary) value of $text
     */
    public function text2bin($text, $strict=false) {
        $bin = base64_decode(strtr($text, '-_', '+/'), $strict);
        return $bin;
    }

    // -------------------------------------------------
    /**
     * Read a textual representation of an integer number.
     *
     * @param  string|array $text A textual representation of a number.
     * @return int if $text is not a number, it is returned AS IS
     */
    public static function text2int($text) {
        if ( is_int($text) ) return $text;
        if ( is_string($text) ) {
            if ( strncmp($text, '0x', 2) == 0 ) {
                return hexdec(substr($text, 2));
            }
            if ( strncmp($text, '0b', 2) == 0 ) {
                return bindec(substr($text, 2));
            }
            if ( is_numeric($text) ) {
                return intval($text);
            }
        }
        if ( is_array($text) ) {
            $ret = array();
            foreach($text as $k => $t) {
                $ret[$k] = self::text2int($t);
            }
            return $ret;
        }

        return $text;
    }
    // -------------------------------------------------
    /**
     * XOR two arrays, item by item, cycling the smaller one.
     *
     * @param  array $a
     * @param  array $b
     * @return array
     */
    public static function arrxor($a,$b) {
        $m = count($a);
        $n = count($b);
        if($m != $n) {
            if(!$m) return $b;
            if(!$n) return $a;
            if( $m < $n ) {
                $c = $a; $a = $b; $b = $c;
                $m = count($a);
                $n = count($b);
            }
        }
        reset($b);
        foreach($a as $k => $v) {
            $a[$k] ^= current($b);
            if ( !next($b) ) reset($b);
        }

        return $a;
    }

    // -------------------------------------------------
    /**
     * XOR two strings char by char, cycling the smaller one.
     *
     * @param  string $a
     * @param  string $b
     * @return string
     */
    public static function strxor($a,$b) {
        $m = strlen($a);
        $n = strlen($b);
        if($m != $n) {
            if(!$m || !$n) return $a . $b;
            if($n < $m) {
                $b = str_repeat($b, floor($m / $n)) . substr($b, 0, $m % $n);
            }
            else {
                $a = str_repeat($a, floor($n / $m)) . substr($a, 0, $n % $m);
            }
        }
        return $a ^ $b;
    }

    // -------------------------------------------------
    /**
     * $a ^ $b
     * @param  string|array $a A string of an array of int
     * @param  string|array $b A string of an array of int
     * @param  int $intSize If $a and/or $b is an array, this is the size of integer items to consider, in bytes.
     * @return string|array If any of $a or $b is string, the result is string.
     */
    public static function mixor($a, $b, $intSize) {
        if ( !isset($a) ) return $b;
        if ( !isset($b) ) return $a;

        if ( is_string($a) ) {
            if ( is_array($b) ) {
                $b = self::arrayOfInt2String($b, $intSize);
            }
        }
        elseif( is_string($b) ) {
            $a = self::arrayOfInt2String($a, $intSize);
        }
        else {
            return self::arrxor($a, $b);
        }

        return self::strxor($a, $b);
    }

    // -------------------------------------------------
    /**
     * Convert an array of integers to binary string repersentation.
     *
     * @param  array $arr
     * @param  int $intSize Number of bytes of each item to consider.
     *                      Auto-calculated from a small sample when missing.
     * @return string binary representation of $arr
     */
    public static function arrayOfInt2String($arr, $intSize=NULL) {
        if ( empty($intSize) ) {
            $v = 0;
            foreach($arr as $k => $i) {
                $s = self::sizeOfInt($i);
                if ( $s > $intSize ) {
                    $intSize = $s;
                    if ( $intSize == PHP_INT_SIZE ) break;
                    $v = 0;
                }
                elseif ( $intSize && ++$v > 16 ) {
                    break;
                }
            }
        }

        $str = '';
        foreach($arr as $k => $i) {
            $s = array();
            for($p=$intSize; $p--;) {
                $s[] = chr($i & 0xFF);
                $i >>= 8;
            }
            $str .= implode('', $s);
        }

        return $str;
    }

    // -------------------------------------------------
    public function env($n) {
        $r = getenv($n);
        if($r === false) $r = isset($_SERVER[$n]) ? $_SERVER[$n] : false;
        return $r;
    }

    // -------------------------------------------------
    /**
     *   Write some random bits to /dev/random or /dev/urandom
     *
     *   From `man 4 random`:
     *      Writing to /dev/random or /dev/urandom will update the entropy pool
     *      with the data written, but this will not result in a higher entropy
     *      count.  This means that it will impact the contents read from both
     *      files, but it will not make reads from /dev/random faster.
     */
    public function seedRandomDev($seed=NULL) {
        $this->seedSys = false; // system random seeded, don't seed again on __destruct()

        // Aditional entropy
        if(isset($seed)) {
            $this->seed($seed);
        }
        $ret = $this->frand_put_content('/dev/random') or
        $ret = $this->frand_put_content('/dev/urandom');
        return $ret;
    }

    // -------------------------------------------------
    /**
     *   Write $length bytes of random data to $filename file.
     *
     *   If $length is not specified, write data from internal buffer.
     */
    public function frand_put_content($filename, $length=NULL, $append=false) {
        $f = @fopen($filename, $append?'c':'w');
        if($f) {
            if(empty($length)) {
                $str = strlen($this->_b) ? $this->_b : $this->seed($filename.$append);
            }
            else {
                $str = $this->str($length);
            }
            if($append) fseek($f, 0, SEEK_END);
            $ret = fwrite($f, $str);
            fclose($f);
            return $ret;
        }
        return false;
    }

    // -------------------------------------------------
    /**
     * Lock with retries
     *
     * @param (resource)$fp - Open file pointer
     * @param (int) $lock - Lock type
     * @param (int) $timeout_ms - Timeout to wait for unlock in miliseconds
     *
     * @return true on success, false on fail
     *
     * @author Dumitru Uzun
     *
     */
    function do_flock($fp, $lock, $timeout_ms=384) {
        $l = flock($fp, $lock);
        if( !$l && ($lock & LOCK_UN) != LOCK_UN ) {
            $st = microtime(true);
            $m = min( 1e3, $timeout_ms*1e3);
            $n = min(64e3, $timeout_ms*1e3);
            if($m == $n) $m = ($n >> 1) + 1;
            $timeout_ms = (float)$timeout_ms / 1000;
            // If lock not obtained sleep for 0 - 64 milliseconds, to avoid collision and CPU load
            do {
                usleep($t = mt_rand($m, $n));
                $l = flock($fp, $lock);
            } while ( !$l && (microtime(true)-$st) < $timeout_ms );
        }
        return $l;
    }

    function flock_put_contents($fn, $cnt, $block=false) {
        // return file_put_contents($fn, $cnt, $block & FILE_APPEND);
        $ret = false;
        if( $f = fopen($fn, 'c+') ) {
            $app = $block & FILE_APPEND and $block ^= $app;
            if( $block ? $this->do_flock($f, LOCK_EX) : flock($f, LOCK_EX | LOCK_NB) ) {
                if(is_array($cnt) || is_object($cnt)) $cnt = serialize($cnt);
                if($app) fseek($f, 0, SEEK_END);
                if(false !== ($ret = fwrite($f, $cnt))) {
                    fflush($f);
                    ftruncate($f, ftell($f));
                }
                flock($f, LOCK_UN);
            }
            fclose($f);
        }
        return $ret;
    }

    function flock_get_contents($fn, $block=false) {
       // return file_get_contents($fn);
       $ret = false;
       if( $f = fopen($fn, 'r') ) {
           if( flock($f, LOCK_SH | ($block ? 0 : LOCK_NB)) ) {
              $s = 1 << 14 ;
              do $ret .= $r = fread($f, $s); while($r !== false && !feof($f));
              if($ret == NULL && $r === false) $ret = $r;
              // filesize result is cached
              flock($f, LOCK_UN);
           }
           fclose($f);
       }
       return $ret;
    }
    // -------------------------------------------------
    function isWindows() {
        return getenv('WINDIR') || getenv('windir');
        // return DIRECTORY_SEPARATOR != '/';
    }
    // -------------------------------------------------

}

if(!function_exists('sys_get_temp_dir')) {
    function sys_get_temp_dir() {
        static $dir;
        if(!isset($dir)) {
            if(!empty($_ENV['TMP'])) { return $dir = realpath($_ENV['TMP']); }
            if(!empty($_ENV['TMPDIR'])) { return $dir = realpath( $_ENV['TMPDIR']); }
            if(!empty($_ENV['TEMP'])) { return $dir = realpath( $_ENV['TEMP']); }
            $tempfile = tempnam(__FILE__, '');
            if(file_exists($tempfile)) {
                unlink($tempfile);
                return $dir = realpath(dirname($tempfile));
            }
            $dir = false;
        }
        return $dir;
    }
}

?>
