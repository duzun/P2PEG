# Peer to Peer Entropy Generator
## or Random numbers generator with p2p seeding
@version 0.4.0  [![Build Status](https://travis-ci.org/duzun/P2PEG.svg?branch=master)](https://travis-ci.org/duzun/P2PEG)

[API Documentation](https://duzun.github.io/P2PEG/docs/)

## About

**Node**: There is a JavaScript version of this library under development [p2peg.js](https://github.com/duzun/p2peg.js).

This class uses a combination of sources of entropy to generate random data as unpredictable as possible.
The key concept is sharing of random data between peers, where both peers benefit from the request.

Internally each peer generates random data using some system data, server performance/load, some [PRNGs](http://en.wikipedia.org/wiki/Pseudorandom_number_generator) (Pseudo Random Number Generators), timing and client supplied data.
The collected data is always combined with the internal state data, which changes at each request, and digested by a [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) with the peer's secret key.

Each client-peer adds to the entropy of the server-peer by suppling variable data with the request (in purpos or not) and by the fact of connecting to the server (the exact request time is also accounted), thus changing internal state of the `P2PEG`.
The internal state is the sum of all collected entropy bits from system and from all client-peers that have ever requested current peer.

For client-peer there is no way to know about `P2PEG`'s internal state or about other client-peers, hence generated data is truly random and unpredictable.

If one peer doesn't trust the other peer to be "honest", it can contact multiple peers to gather the random bits and combine the result with it's own PRN and internal state.

On a web-server entropy can also be collected from common website clients.


## Basic Usage

Include the class

```php
require_once "/path/to/lib/P2PEG.php";
```

Get the singleton instance or just create a new instance of P2PEG

```php
$P2PEG = P2PEG::instance();
```

Get some random binary string

```php
$str = $P2PEG->str($length);
```

Now you can use `$str` as cryptographic salt, seed for PRNG, password generators or anything else that requires unpredictable hight entropy data.

Get some random integer numbers:

```php
$int1 = $P2PEG->int();
$int2 = $P2PEG->int16();
$int3 = $P2PEG->int32();
```

Get some random text (base64 encoded)

```php
$text = $P2PEG->text($length);
```

Get some random string hex encoded

```php
$hex = $P2PEG->hex($length);
```

Get a pseudo random 32bit integer - this method is faster then int32() for generating lots of numbers, but in turn it uses less entropy (see [RNG](http://en.wikipedia.org/wiki/Random_number_generation)).

```php
$rand_int = $P2PEG->rand32();
```

Get a pseudo random 64bit integer - this method is faster then int() for generating lots of numbers, but in turn it uses less entropy (see [xorshiftplus](http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf) algorithm).


```php
$rand_long = $P2PEG->rand64();
```

## Advanced Usage

Before using the instance of `P2PEG` class, it is a good idea to set some properties:

Internal state file - optional. Tip: Keep it inaccessible to other users on system by `chmod 0600 p2peg.dat`

```php
$P2PEG->state_file = "/path/to/data/p2peg.dat";
```

A secret key chosen at setup

```php
$P2PEG->setSecret("some uniq secret that no one knows");
```

Seed the P2PEG with some bits of data or your choise

```php
$P2PEG->seed("some (random) string");
```

Seed the PHP's RNG

```php
mt_srand(crc32($P2PEG->seed()));
```

Write to `/dev/random`

```php
$P2PEG->seedRandomDev("some (optional) entropy");
```

Get a 56bit integer, if system is x64

```php
$int64 = $P2PEG->int(7);
```

Display a random bitmap image

```php
$P2PEG->servImg($width,$height,$method='rand32',$itemSize=0);
```

Take care of what `$method` you allow for `servImg()`, cause it could display some private data to client.
The following methods are safe to display to client:

```php
$allowMethods = array('rand32', 'int','int32','int16','str','seed','text','hex','dynEntropy','clientEntropy','networkEntropy');
```

This method helps to visually inspect a random number generator (RNG). It is not enough to know how good the RNG is, but it can tell that the RNG is bad or something is wrong.

Examples:
- https://duzun.me/entropy/img/rand32
- https://duzun.me/entropy/img/rand64/64
- https://duzun.me/entropy/img/str


Get some entropy from outside

```php
$P2PEG->networkEntropy($autoseed=true);
```

On cron event you could call

```php
$P2PEG->expensiveEntropy($autoseed=true);
```

This method gathers some network entropy and server entropy and can be realy slow. This is why it is a good idea to call it in background. But at the same time it is a good idea to call it from time to time, to get some more unpredictable, crtypto-safe entropy.

 ... more comming soon


## Sample output

https://duzun.me/entropy

![Randomness Visualisation](https://duzun.me/entropy/img)

## TODO

1. To improve the entropy unpredictability, I intend to create system where multiple machines periodically exchange entropy.
Each pear gets entropy and gives entropy at the same time with a simple GET request like this one:

    `curl "https://DUzun.Me/entropy/<hash(random_func().$secret)>"`

2. Seed `/dev/random` and update entropy count, to improve system performance

3. Count the amount of entropy generated

4. Test the quality of entropy witth [TestU01](http://simul.iro.umontreal.ca/testu01/tu01.html)

5. Create a JavaScript version (in development [here](https://github.com/duzun/p2peg.js))

