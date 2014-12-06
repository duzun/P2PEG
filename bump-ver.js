/*
 *  Ussage:
 *    node bump-ver +<revision> [+<minor> [+<major>]]
 */


var files = ['P2PEG.php', 'README.md'];
var ver_reg = /((?:\$|@)version[\s='"]+)([0-9]+(?:\.[0-9]+)+)/;


var path = require('path');
var fs = require('fs');


var packFile = path.join(__dirname, 'package.json');
var pack = fs.readFileSync(packFile);
var packo = JSON.parse(pack);

var over = packo && packo.version;

var bump = process.argv.slice(2);
if ( bump.length == 0 ) bump = [1];


if ( over ) {
  var nver = over
    .split('.')
    .reverse()
    .map(function (n, i) {
        return (i = bump[i] | 0) ? +n + i : n;
    })
    .reverse()
    .join('.')
  ;
  packo.version = nver;

  var buf = JSON.stringify(packo, null, 2);

  if ( buf && buf != pack ) {
    fs.writeFileSync(packFile, buf);
  }

  files.forEach(function (f) {
    var fn = path.join(__dirname, f);
    var cnt = fs.readFileSync(fn, 'utf8');
    buf = cnt
    .split('\n')
    .map(function (l) {
        return ver_reg.test(l)
          ? l.replace(ver_reg, function ($0,$1) { return $1 + nver })
          : l
        ;
    })
    .join("\n");
    if ( buf && buf != cnt ) {
      fs.writeFileSync(fn, buf);
    }
  });

}
