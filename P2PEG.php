<?php
/*!
 *  Peer to Peer Entropy Generator
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
 *  @version 0.0.1-alpha
 *  @author Dumitru Uzun (DUzun.Me)
 *
 */

class P2PEG {
    static $start_ts;
    static protected $instance; // singleton

    private $_secret = ',!8L_J:UWWl\'ACt:7c05!R8}~>yb!gPP=|(@FBny\'ao/&-\jVs';

    public $state_file;

    public $debug = false;

    // Use first available hash alg from the list
    public $hash = array('sha512', 'sha256', 'sha128', 'sha1', 'md5');


    // State values
    private $_state;
    protected $_clientEntropy;
    protected $_serverEntropy;
    protected $_stateEntropy;

    // -------------------------------------------------
    static function instance() {
        if(!isset(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    // -------------------------------------------------
    public function __construct() {
        // parent::__construct();
        isset(self::$start_ts) or self::$start_ts = microtime(true);
    }

    public function __destruct() {
        // parent::__destruct();
        if($this->_state && $this->state_file) {
            // Save state somewhere
            @$this->flock_put_contents($this->state_file, $this->_state);
        }
    }
    // -------------------------------------------------
    public function generate($raw=true) {
        $ret =  $this->state()
                . $this->serverEntropy()
                . $this->clientEntropy()
                . $this->dynEntropy()
        ;
        $ret = $this->hash($ret);
        $this->_state ^= $ret;
        return $raw ? $ret : bin2hex($ret);
    }

    // -------------------------------------------------
    public function setSecret($secret) {
        $this->_secret = $secret;
    }
    // -------------------------------------------------
    /*
     * Each connecting client brings in some entropy.
     * Server entropy state is influenced by each client.
     */
    public function clientEntropy() {
        if(!isset($this->_clientEntropy)) {
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
            // HTTP_COOKIE and REQUEST_URI might contain private data - hash/hide it at this point
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

    public function dynEntropy($quick=true) {
        $_entr = array();

        $_entr[$this->packInt(substr(microtime(), 2, 6))] = 'microtime';
        $_entr[$this->packInt(rand())] = 'rand';

        // Get some data from mt_rand()
        $r = array();
        $l = rand(2,8);
        for ($i = 0; $i < $l; ++$i) $r[] = pack('S', mt_rand(0, 0xffff));
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

    public function state() {
        if(!isset($this->_state)) {
            if(!$this->state_file) {
                $this->state_file = sys_get_temp_dir() . DS . __CLASS__ . '.dat';
            }
            $state_file = $this->state_file;
            if($state_file) {
                if(file_exists($state_file)) {
                    // We could use filemtime($state_file) as entropy too
                    $this->_state = $this->flock_get_contents($state_file);
                }
                else {
                    is_dir($dir = dirname($state_file)) or mkdir($dir, 0600, true);
                }
            }
            $entr = $this->hash($this->dynEntropy());
            // No state - init it with random data
            if(!$this->_state) {
                $this->_state = $entr;
            }
            // Update state before next save
            else {
                // Align state value with our hash function
                if(strlen($this->_state) < strlen($entr)) {
                    $this->_state = $this->hash(entr.$this->_state);
                }
                // Change state
                $this->_state ^= $entr;
            }
        }
        return $this->_state;
    }

    // -------------------------------------------------

    public function hash($str, $raw=true) {
        $str = $str . $this->_secret;
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
    public function packIP4($ip, $hex=NULL) {
        $ip = explode('.', $ip);
        if(count($ip) < 4) return $ip; // invalid IP
        $r = 0;
        for($i=0; $i<4; $i++) $r = ($r << 8) | (int)$ip[$i];
        return pack('L', $r);
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



return P2PEG::instance();




?>
