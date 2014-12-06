
var spawn = require('child_process').spawn;
var watch = require('watch');
var path  = require('path');

var _to      = null;
var _delay   = 300;
var _running = null;
var _dir     = path.join(__dirname, '..');

function run_test() {
    _to = null;

    if ( _running ) {
      console.log('In the process...');
      return;
    }

    console.log('\n\x1b[36m --- Running PHPUnit ... ---\x1b[0m\n');

    _running = spawn(
      'phpu.cmd'
      , ['tests/TestP2PEG.php']
      , { cwd: _dir, env: process.env }
    );

    _running.stdout.pipe(process.stdout);
    _running.stderr.pipe(process.stderr);

    // Coult use on('data') instead of pipe(),
    // but pipe() streams data as soon as available:
    // var out = ''
    // ,   err = ''
    // ;
    // _running.stdout.on('data', function (data) { out += data; });
    // _running.stderr.on('data', function (data) { err += data; });

    _running.on('close', function (code) {
      // out && console.log(out);
      // err && console.log(err);

      // Have errors
      if ( code ) {
        console.log('\x1b[31mFAIL (%d)\x1b[0m', code);
      }
      // Ok
      else {
        console.log('\x1b[32mPASS All\x1b[0m');
      }
      _running = null;
    });
}

function run_test_async() {
    if ( _to ) {
      clearTimeout(_to);
    }
    _to = setTimeout(run_test, _delay);
}

run_test_async();

watch.createMonitor(
  _dir
  , {
    interval: _delay >>> 1
    , ignoreDotFiles: true
    , ignoreDirectoryPattern: /(node_modules|scripts)/
    , filter: function (f, stat) { return stat.isDirectory() || path.extname(f) === '.php'; }
  }
  , function (monitor) {
    // monitor.files['/home/mikeal/.zshrc'] // Stat object for my zshrc.
    monitor.on("created", function (f, stat) {
      run_test_async()
    })
    monitor.on("changed", function (f, curr, prev) {
      run_test_async()
    })
    monitor.on("removed", function (f, stat) {
      run_test_async()
    })
    // monitor.stop(); // Stop watching
  }
);



