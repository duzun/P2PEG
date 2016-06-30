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
 *  @version 0.3.3
 *  @author Dumitru Uzun (DUzun.Me)
 *
 */

class P2PEG {
    public static $version = '0.3.3';

    // First start timestamp
    public static $start_ts;

    // Singleton instance
    protected static $instance;

    /// Path to a file where to store state data
    public $state_file;

    public $debug = false;

    /// Use first available hash alg from the list
    public $hash = array('sha512', 'sha256', 'sha128', 'sha1', 'md5');

    // Padding for HMAC-HASH
    private $_opad, $_ipad;

    // If true, call seedRandomDev() on __destruct
    public $seedSys = true;

    // Seed for rand32() & rand64() methods
    public $rs00 = 0;
    public $rs01 = 0;
    public $rs10 = 0;
    public $rs11 = 0;

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
    public function __construct($secret=',!8L_J:UW~l\'ACt:7c05!R9}~>yb!gPP=|(@FBny\'ao/&-\jVs') {
        // parent::__construct();
        isset(self::$start_ts) or self::$start_ts = microtime(true);
        $this->setSecret($secret);
        isset(self::$int_len) or self::$int_len = round(PHP_INT_SIZE * log10(256));

        $this->seedSys = !$this->isWindows();
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
     *  Base64 encoded text for URL
     */
    public function text($len=NULL) {
        $l = isset($len) ? ceil((float)$len * 3.0 / 4.0) : NULL;
        $ret = $this->bin2text($this->str($l));
        if(isset($len) && strlen($ret) > $len) $ret = substr($ret, 0, $len);
        return $ret;
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
     *  Pseudo-random 32bit integer numbers generator.
     *
     *  This function produces same result as $this->int32(),
     *  but is much faster at generating long strings of random numbers,
     *  and uses less entropy as well.
     *
     *  @source http://en.wikipedia.org/wiki/Random_number_generation
     *
     *  @return  (int)random
     */
    public function rand32() {
        $rs10 = $this->rs10;
        $rs00 = $this->rs00;

        // Seed if necessary
        while(!$rs10 || $rs10 == 0x464fffff) {
            /* must not be zero, nor 0x464fffff */
            $rs10 = $this->int32() ^ $this->int32();
        }
        while(!$rs00 || $rs00 == 0x9068ffff) {
            /* must not be zero, nor 0x9068ffff */
            $rs00 = $this->int32() ^ $this->int32();
        }

        $rs00 = 0x9069 * ($rs00 & 0xFFFF) + ($rs00 >> 16);
        $rs10 = 0x4650 * ($rs10 & 0xFFFF) + ($rs10 >> 16);
        $ret = ($rs00 << 16) + $rs10;  /* 32-bit result */

        $this->rs10 = $rs10;
        $this->rs00 = $rs00;

        // handle overflow:
        // in PHP at overflow (int32) -> (float)
        return $ret | 0;
    }

    // -------------------------------------------------
    /**
     *  Pseudo-random 64bit integer numbers generator.
     *
     *  @source  http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf
     *
     *  @return (int)random
     */
    public function rand64() {
        $s10 = $this->rs00;
        $s11 = $this->rs01;
        $s00 = $this->rs10;
        $s01 = $this->rs11;

        $m = 0xFFFFFFFF;

        // Seed if necessary
        while(!$s10 || !$s11) {
            $s10 = $this->int32();
            $s11 = $this->int32();
        }
        while(!$s00 || !$s01) {
            $s00 = $this->int32();
            $s01 = $this->int32();
        }

        $this->rs00 = $s00;
        $this->rs01 = $s01;

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

        $this->rs10 = $s10;
        $this->rs11 = $s11;

        return (($this->rs01 + $this->rs11) << 32) + ($this->rs00 + $this->rs10);
    }
    // -------------------------------------------------
    /**
     *  Generate and serve to client a random bitmap image.
     *
     *  This method helps to visually inspect a random number generator (RNG).
     *  It is not enough to know how good the RNG is,
     *  but it can tell that the RNG is bad or something is wrong.
     *
     *  @param (int)$width of the image
     *  @param (int)$height of the image
     *  @param (str)$meth - a method of this class to generate data
     *  @param (int)$itemSize in bits - size of each number or char generated by $meth. Defaults to 8 for string and 32 for int
     *
     *  @note Requires the GD Library
     *
     *  Inspired by  http://boallen.com/random-numbers.html
     *
     */
    public function servImg($width=64, $height=64, $meth='rand32', $itemSize=NULL) {
        header("Content-type: image/png");
        $im = imagecreatetruecolor($width, $height) or die("Cannot Initialize new GD image stream");
        $white = imagecolorallocate($im, 255, 255, 255);
        // @TODO: Check if $method is safe to display to client
        $g = $this->$meth();
        $iss = is_string($g); // string or int32
        if($iss) {
            $p = strlen($g);
            $r = ord(substr($g, --$p, 1));
            $bitSize = empty($itemSize) ? 8 : $itemSize; // 1 bytes == 8 bits
        }
        else {
            $r = $g;
            $bitSize = empty($itemSize) ? 32 : $itemSize; // 4 bytes == 32 bits
        }
        $i = $bitSize;

        for($y = 0; $y < $height; $y++) {
            for($x = 0; $x < $width; $x++) {
                if($i == 0) {
                    if($iss) {
                        if(!$p) {
                            $g = $this->$meth();
                            $p = strlen($g);
                        }
                        $r = ord(substr($g, --$p, 1));
                    }
                    else {
                        $r = $this->$meth();
                    }
                    $i = $bitSize;
                }
                if($r & 1) {
                    imagesetpixel($im, $x, $y, $white);
                }
                $r >>= 1;
                --$i;
            }
        }
        imagepng($im);
        imagedestroy($im);
    }

    // -------------------------------------------------
    public function setSecret($key) {
        $size = 64;
        $l = strlen($key);
        if($size < $l) {
            $key = hash('sha1', $key, true);
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
        $_entr[$this->packInt(rand())] = 'rand';

        // Get some data from mt_rand()
        $r = array();
        $l = rand(1,8);
        for ($i = 0; $i < $l; ++$i) $r[] = pack('S', mt_rand(0, 0xFFFF));
        $r = implode('', $r);
        $_entr[$r] = 'mt_rand';

        // System performance/load indicator
        $r = (microtime(true)-self::$start_ts)*1000;
        $_entr[$this->packFloat($r)] = 'delta';

        $_entr = implode('', array_keys($_entr));
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
                $_entr = implode('', $argv);
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
            $_entr = implode('', array_keys($_entr));
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

            $_entr = implode('', array_keys($_entr));
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
            $_entr[php_uname('s')] = 's'; // 'Linux' - less usefull, cause it never changes
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

            if(function_exists('mcrypt_create_iv')) {
                $t = mcrypt_create_iv(32) and
                $_entr[$t] = 'mcrypt_create_iv';
            }

            $_entr[$this->packFloat(self::$start_ts)] = 'start';

            $_entr = implode('', array_keys($_entr));
            $this->_serverEntropy = $_entr;
        }
        return $this->_serverEntropy;
    }

    // -------------------------------------------------
    public function filesystemEntropy($dirs=NULL, $maxRead=0) {
        if(!isset($dirs)) {
            if(isset($this->_filesystemEntropy)) return $this->_filesystemEntropy;
            $_save_result = true;
            $dirs = array(session_save_path(), sys_get_temp_dir(), $this->env('DOCUMENT_ROOT'));
        }
        if(!$maxRead) {
            $maxRead = rand(100,500);
        }
        if(!$dirs) return false;

        if(!is_array($dirs)) $dirs = array($dirs);

        // Unique
        $dirs = array_flip($dirs);

        $buf = '';
        foreach($dirs as $dir => $v) if($d = @opendir($dir)) {
            $h = $this->strxor((($v+1)*$maxRead) . $d . $this->packInt(filemtime($dir)), $dir);
            $i = $maxRead;
            while($i-- > 0 and $f = readdir($d)) if($f != '.' && $f != '..') {
                $h = $this->strxor($h, $f);
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

        $_entr = implode('', array_keys($_entr));

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

    public function hash($str, $raw=true) {
        $str = $this->_ipad . $str;
        if(is_array($this->hash)) {
            foreach($this->hash as $h) {
                $ret = hash($h, $str, true);
                if($ret !== false) {
                    $this->hash = $h;
                    return hash($h, $this->_opad . $ret, $raw);
                }
            }
            $this->hash = 'sha1'; // minimum required sha1
        }
        $ret = hash($this->hash, $this->_opad . hash($this->hash, $this->_ipad . $str, true), $raw);
        return $ret;
    }
    // -------------------------------------------------

    // Helper methods:

    public function packIP4($ip) {
        $r = '';
        $ip = explode('.', $ip);
        $hasNaN = false;
        foreach($ip as $i) {
            $t = +($i=trim($i));
            if ( !$t && strncmp($i, '0', 1) ) {
                $hasNaN = true;
                continue;
            }
            $r .= chr($t & 0xFF);
        }
        if ( $hasNaN && !strlen($r) ) return false;
        return $r;
    }

    public function packInt($int) {
        $r = '';
        if(is_string($int)) {
            $int = ltrim($int, '0.');
            if(strlen($int) > self::$int_len) {
                $i = str_split($int, self::$int_len);
                foreach($i as $v) $r .= $this->packInt(+$v);
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

    public function packFloat($float) {
        $t = explode('.', $float, 2);
        return count($t) == 2
            ? $this->packInt($t[1].$t[0]).$this->packInt(strlen($t[1]))
            : $this->packInt($float)
        ;
    }

    // -------------------------------------------------
    public function bin2text($bin) {
        $text = strtr(rtrim(base64_encode($bin), '='), '+/', '-_');
        return $text;
    }

    public function text2bin($text, $strict=false) {
        $bin = base64_decode(strtr($text, '-_', '+/'), $strict);
        return $bin;
    }

    // -------------------------------------------------
    public function strxor($a,$b) {
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
                usleep($t = rand($m, $n));
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
