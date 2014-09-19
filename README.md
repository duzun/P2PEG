
# Peer to Peer Entropy Generator
## or Random data generator with p2p seeding
@version 0.1.0

## About

This class uses a combination of sources of entropy to generate random data as unpredictable as posible. 
The key concept is sharing of random data between peers, where each peer benefits from each request.

Internally each peer generates random data using some system data, server performance/load, some PRNGs (Pseudo random Number Generators) available to PHP, timing and client supplied data. This way the generated data apears unpredictable to the connecting peer and at the same time is also influenced by the connecting peer.

If the peer doesn't trust the other peer to be "honest", it can contact multiple peers to gather the random bits. And the collected data is always combinet with the peer's secred and some internat random data.

Each peer adds to the entropy of the other peer by suppling variable data with the request (in purpos or not) and by the fact of connecting to the server (the exact request time is also accounted), thus changing internal state of the `P2PEG`.

For connecting peers there is no way to know about `P2PEG`'s internal state or about other connecting peers, hence generated data is truly random.


## Basic Usage

    // Include the class
    require_once "/path/to/lib/P2PEG.php";
    
    // Get the singleton instance or just create a new instance of P2PEG
    $P2PEG = P2PEG::instance();
    
    // Get some random binary string
    $str = $P2PEG->str($length);

Now you can use `$str` as cryptographic salt, seed for PRNG, password generators or anything else that requires unpredictable hight entropy data.
    
    // Get some random integer numbers
    $int1 = $P2PEG->int();
    $int2 = $P2PEG->int16();
    $int3 = $P2PEG->int32();
    
    // Get some random text (base64 encoded)
    $text = $P2PEG->text($length);
    
    // Get some random string hex encoded
    $hex = $P2PEG->hex($length);


## Advanced Usage

Before using the instance of `P2PEG` class, it is a good idea to set some properties:

    // optional - keep this file inaccessible to other users on system by `chmod 0600 p2peg.dat`
    $P2PEG->state_file = "/path/to/data/p2peg.dat";
    
    // A secret key chosen at setup
    $P2PEG->setSecret("some uniq secret that no one knows");

    // Generate a string of random bits
    $P2PEG->seed("some (random) string");
    
    // Seed the PHP's RNG
    mt_srand(crc32($P2PEG->seed()));
    

    // ... and so on

## TODO

To improve the entropy unpredictability, I intend to create system where multiple machines periodically exchange entropy. 
Each pear gets entropy and gives entropy at the same time with a simple GET request like this one:

    curl https://DUzun.Me/entropy/<hash(random_func().$secret)>


