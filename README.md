
# Peer to Peer Entropy Generator
## or Random numbers generator with p2p seeding
@version 0.1.3

## About

This class uses a combination of sources of entropy to generate random data as unpredictable as posible. 
The key concept is sharing of random data between peers, where each peer benefits from each request.

Internally each peer generates random data using some system data, server performance/load, some PRNGs (Pseudo Random Number Generators) available to PHP, timing and client supplied data. This way the generated data apears unpredictable to the connecting peer and at the same time is also influenced by all connecting peers.

If the peer doesn't trust the other peer to be "honest", it can contact multiple peers to gather the random bits. And the collected data is always combinet with the peer's secred and some internat random data.

Each peer adds to the entropy of the other peer by suppling variable data with the request (in purpos or not) and by the fact of connecting to the server (the exact request time is also accounted), thus changing internal state of the `P2PEG`.

For connecting peers there is no way to know about `P2PEG`'s internal state or about other connecting peers, hence generated data is truly random.

Entropy can also be collected from common website clients.

## Basic Usage

Include the class

    require_once "/path/to/lib/P2PEG.php";
    
Get the singleton instance or just create a new instance of P2PEG

    $P2PEG = P2PEG::instance();
    
Get some random binary string

    $str = $P2PEG->str($length);

Now you can use `$str` as cryptographic salt, seed for PRNG, password generators or anything else that requires unpredictable hight entropy data.
    
Get some random integer numbers:

    $int1 = $P2PEG->int();
    $int2 = $P2PEG->int16();
    $int3 = $P2PEG->int32();
    
Get some random text (base64 encoded)

    $text = $P2PEG->text($length);
    
Get some random string hex encoded

    $hex = $P2PEG->hex($length);

Get a pseudo random 32bit integer - this method is faster then int32() for generating lots of numbers, but in turn it uses less entropy

    $rand_int = $P2PEG->rand32();

## Advanced Usage

Before using the instance of `P2PEG` class, it is a good idea to set some properties:

Internal state file - optional. Tip: Keep it inaccessible to other users on system by `chmod 0600 p2peg.dat`

    $P2PEG->state_file = "/path/to/data/p2peg.dat";
    
A secret key chosen at setup

    $P2PEG->setSecret("some uniq secret that no one knows");

Seed the P2PEG with some bits of data or your choise

    $P2PEG->seed("some (random) string");
    
Seed the PHP's RNG

    mt_srand(crc32($P2PEG->seed()));
    
Get a 56bit integer, if system is x64

    $int64 = $P2PEG->int(7);

Display a random bitmap image

    $P2PEG->servImg($width,$height,$method='rand32',$itemSize=0);
    
Take care of what `$method` you allow for `servImg()`, cause it could display some private data to client.
The following methods are safe to display to client:

    $allowMethods = array('rand32', 'int','int32','int16','str','seed','text','hex','dynEntropy','clientEntropy','networkEntropy');

This method helps to visually inspect a random number generator (RNG). It is not enough to know how good the RNG is, but it can tell that the RNG is bad or something is wrong.

Examples:
- https://duzun.me/entropy/img/rand32
- https://duzun.me/entropy/img/str


Get some entropy from outside
    
    $P2PEG->networkEntropy($autoseed=true);

On cron event you could call

    $P2PEG->expensiveEntropy($autoseed=true);
    
This method gathers some network entropy and server entropy and can be realy slow. This is why it is a good idea to call it in background. But at the same time it is a good idea to call it from time to time, to get some more unpredictable, crtypto-safe entropy.

 ... more comming soon
    

## Sample output

https://duzun.me/entropy


## TODO

To improve the entropy unpredictability, I intend to create system where multiple machines periodically exchange entropy. 
Each pear gets entropy and gives entropy at the same time with a simple GET request like this one:

    curl https://DUzun.Me/entropy/<hash(random_func().$secret)>



