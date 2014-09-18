
# Peer to Peer Entropy Generator
## or Random data generator with p2p seeding
@version 0.0.1-a

## About

This class uses a combination of sources of entropy to generate random data as unpredictable as posible. 
The key concept is sharing of random data between peers, where each peer benefits from each request.

Internally each peer generates random data using some system data, server performance/load, some PRNGs (Pseudo random Number Generators) available to PHP, timing and client supplied data. This way the generated data apears unpredictable to the connecting peer and at the same time is also influenced by the connecting peer.

If the peer doesn't trust the other peer to be "honest", it can contact multiple peers to gather the random bits. And the collected data is always combinet with the peer's secred and some internat random data.

Each peer adds to the entropy of the other peer by suppling variable data with the request (in purpos or not) and by the fact of connecting to the server (the exact request time is also accounted), thus changing internal state of the `P2PEG`.

For connecting peers there is no way to know about `P2PEG`'s internal state or about other connecting peers, hence generated data is truly random.


## Usage

    $P2PEG = include "/path/to/lib/P2PEG.php";
    
    // optional - keep this file inaccessible to other users on system by `chmod 0600 p2peg.dat`
    $P2PEG->state_file = "/path/to/data/p2peg.dat";
    
    // A secret key chosen at setup
    $P2PEG->setSecret("some uniq secret that no one knows");

    // Generate a string of random bits
    $random_seed = $P2PEG->generate(true);
    
    // Seed the PHP's RNG
    mt_srand(crc32($random_seed));
    
    // ... use $random_seed as cryptographic salt, seed for PRNG, password generators or anything else that requires unpredictable hight entropy data.
    
    // Generateanothher random string
    $random_seed2 = $P2PEG->generate(true);
    
    // ... and so on

## TODO

To improve the entropy unpredictability, I intend to create system where multiple machines periodically exchange entropy. 
Each pear gets entropy and gives entropy at the same time with a simple GET request like this one:

    curl https://DUzun.Me/entropy/<hash(random_func().$secret)>


