<?php
/*!
 *  Peer to Peer Entropy Generator
 *  * or Random numbers generator with p2p seeding
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
 *      To improve the entropy unpredictability, I intend to create system
 *      where multiple machines periodically exchange entropy.
 *      Each pear gets entropy and gives entropy at the same time
 *      with a simple GET request like this one:
 *
 *      curl https://DUzun.Me/entropy/<hash(random_func().$secret)>
 *
 *
 *  @version 0.1.2
 *  @author Dumitru Uzun (DUzun.Me)
 *
 */

class P2PEG {
    static $version = '0.1.2';

    // First start timestamp
    static $start_ts;

    // Singleton instance
    static protected $instance;

    /// A secred string, should be unique on each instalation
    private $_secret = ',!8L_J:UWWl\'ACt:7c05!R8}~>yb!gPP=|(@FBny\'ao/&-\jVs';

    /// Path to a file where to store state data
    public $state_file;

    public $debug = false;

    /// Use first available hash alg from the list
    public $hash = array('sha512', 'sha256', 'sha128', 'sha1', 'md5');


    // State values
    private $_state;
    private $_state_mtime;
    protected $_clientEntropy;
    protected $_serverEntropy;
    protected $_filesystemEntropy;

    // internal buffer
    private $_b = '';

    // Seed for rand32() method
    public $rs_z = 0;
    public $rs_w = 0;

    // -------------------------------------------------
    /// Get the singleton instance
    static function instance($secret=NULL) {
        if(!isset(self::$instance)) {
            self::$instance = new self($secret);
        }
        return self::$instance;
    }
    // -------------------------------------------------
    public function __construct($secret=NULL) {
        // parent::__construct();
        isset(self::$start_ts) or self::$start_ts = microtime(true);
        $this->setSecret(isset($secret) ? $secret : $this->_secret);
    }

    public function __destruct() {
        // parent::__destruct();
        
        // Save state to a file
        if($this->_state and $sf = $this->state_file) {
            // If meanwhile state file changed, don't loose that entropy
            clearstatcache(true, $sf);
            $flags = 1;
            if(@filemtime($sf) != $this->_state_mtime) {
                $flags |= FILE_APPEND;
            }
            // @TODO: Watch for state file size if the server is very busy
            
            @$this->flock_put_contents($sf, $this->_state, $flags);
        }
    }
    // -------------------------------------------------
    public function warmup($secret=NULL) {
        isset($secret) and $this->setSecret($secret);
        $this->state();
        $this->serverEntropy();
        $this->clientEntropy();
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
        return $ret;
    }

    // -------------------------------------------------
    /**
     *  Return a random binary string of specified length.
     */
    public function str($len=NULL) {
        $l = strlen($ret = $this->_b) or
        $l = strlen($ret = $this->seed($len));
        isset($len) or $len = $l;
        while($l < $len) {
            $ret .= $this->seed($l);
            $l = strlen($ret);
        }
        if($len < $l) {
            $this->_b = substr($ret, $len);
            $ret = substr($ret, 0, $len);
        }
        else {
            $this->_b = '';
        }
        return $ret;
    }


    /**
     *  Hex encoded string
     */
    public function hex($len=NULL) {
        $l = isset($len) ? $len / 2 : $len;
        $ret = $this->str($l);
        return bin2hex($ret);
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
     *  but is much faster at generating long strings of random numbers.
     *
     *  @source http://en.wikipedia.org/wiki/Random_number_generation
     */
    public function rand32() {
        $rs_w = $this->rs_w;
        $rs_z = $this->rs_z;

        // Seed if necessary
        while(!$rs_w || $rs_w == 0x464fffff) $rs_w = $this->int32() ^ $this->int32();  /* must not be zero, nor 0x464fffff */
        while(!$rs_z || $rs_z == 0x9068ffff) $rs_z = $this->int32() ^ $this->int32();  /* must not be zero, nor 0x9068ffff */

        $rs_z = 36969 * ($rs_z & 0xFFFF) + ($rs_z >> 16);
        $rs_w = 18000 * ($rs_w & 0xFFFF) + ($rs_w >> 16);
        $ret = ($rs_z << 16) + $rs_w;  /* 32-bit result */

        $this->rs_w = $rs_w;
        $this->rs_z = $rs_z;

        return $ret;
    }

    // -------------------------------------------------
    /**
     *  Generate and serve to client a random bitmap image.
     *
     *  This method helps to visually inspect a random number generator (RNG).
     *  It is not enough to know how good the RNG is,
     *  but it can tell that the RNG is bad or something is wrong.
     *
     *  @note Requires the GD Library
     *
     *  Inspired by  http://boallen.com/random-numbers.html
     *
     */
    public function servImg($width=64, $height=64, $meth='rand32') {
        header("Content-type: image/png");
        $im = imagecreatetruecolor($width, $height) or die("Cannot Initialize new GD image stream");
        $white = imagecolorallocate($im, 255, 255, 255);

        // @TODO: Check if $method is save to display to client
        $g = $this->$meth();
        $iss = is_string($g); // string or int32
        if($iss) {
            $p = strlen($g);
            $r = ord(substr($g, --$p, 1));
            $bitSize = 8; // 1 bytes == 8 bits
        }
        else {
            $r = $g;
            $bitSize = 32; // 4 bytes == 32 bits
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
    public function setSecret($secret) {
        // For performance bust, digest the secret
        $this->_secret = hash('sha1', $secret, true);
    }
    // -------------------------------------------------
    /**
     *   Quickly get some dynamic entropy.
     */
    public function dynEntropy($quick=true) {
        $_entr = array();

        $_entr[$this->packInt(substr(microtime(), 2, 6))] = 'microtime';
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

        if($this->debug) {
            echo PHP_EOL; var_export(array(__FUNCTION__ => $_entr)); echo PHP_EOL;
        }

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

            if(strncmp(php_sapi_name(), 'cgi', 3) == 0) {
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
                $_entr[$this->packInt($r)] = 'rt';
            }

            if($this->debug) {
                echo PHP_EOL; var_export(array(__FUNCTION__ => $_entr)); echo PHP_EOL;
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

            if(function_exists('mcrypt_create_iv')) {
                $t = mcrypt_create_iv(16) and
                $_entr[$t] = 'mcrypt_create_iv';
            }

            // On unixy sustems the numerical values in ps, uptime and iostat ought to be fairly
            // unpredictable. Gather the non-zero digits from those
            /* // @TODO: Too slow, move it to cron jobs or somewhare else else...
            foreach (array('ps', 'uptime', 'iostat') as $cmd) {
                @exec($cmd, $s, $ret);
                if (is_array($s) && $s && $ret === 0) {
                    foreach ($s as $v) {
                        if (false !== preg_match_all('/[1-9]+/', $v, $m) && isset($m[0])) {
                            $_entr[implode('', $m[0])] = $cmd;
                        }
                    }
                }
            }
            */
            $_entr[$this->packFloat(self::$start_ts)] = 'start';

            if($this->debug) {
                echo PHP_EOL; var_export(array(__FUNCTION__ => $_entr)); echo PHP_EOL;
            }

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

    public function state() {
        if(!isset($this->_state)) {
            if(!$this->state_file) {
                $this->state_file = sys_get_temp_dir() . DS . __CLASS__ . '.dat';
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
                    $this->filesystemEntropy() // could be a bit expensive, but it is run only the first time
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
        $str .= $this->_secret;
        if(is_array($this->hash)) {
            foreach($this->hash as $h) {
                $ret = hash($h, $str, $raw);
                if($ret !== false) {
                    $this->hash = $h;
                    return $ret;
                }
            }
            $this->hash = 'sha1'; // minimum required sha1
        }
        $ret = hash($this->hash, $str, $raw);
        return $ret;
    }

    // -------------------------------------------------

    // Helper methods:

    public function packIP4($ip) {
        $r = '';
        $ip = explode('.', $ip);
        foreach($ip as $i) $r .= chr($i & 0xFF);
        if($this->debug) $r = bin2hex($r);
        return $r;
    }

    public function packInt($int) {
        $r = '';
        $m = $int < 0 ? -1 : 0;
        while($int != $m) {
            $r .= chr($int & 0xFF);
            $int >>= 8;
        }
        if($this->debug) $r = bin2hex($r);
        return $r;
    }

    public function packFloat($float) {
        $t = explode('.', $float, 2);
        return count($t) == 2 ? $this->packInt($t[1]).$this->packInt($t[0]).$this->packInt(strlen($t[1])) : $this->packInt($float);
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
        if(!$l && ($lock & LOCK_UN) != LOCK_UN && ($lock & LOCK_NB) != LOCK_NB ) {
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
              if(false !== ($ret = fwrite($f, $cnt))) ftruncate($f, ftell($f));
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
