
# Peer to Peer Entropy Generator
@version 0.0.1-alpha

## About

This class uses a combination of system data, client supplied data, server performance/load, some PRNGs available to PHP and timing to generate unpredictable hight entropy data.

Each pear adds to the entropy, by suppling variable data with the request (in purpos or not) and by the fact of connecting to the server (the exact request time is also accounted), thus changing internal state of the `P2PEG`.

For connecting pears there is no way to know about `P2PEG`'s internal state or about other connecting pears, hence generated data is truly random.


## Usage

    $P2PEG = include "/path/to/lib/P2PEG.php";
    
    // optional - keep this file inaccessible to other users on system by `chmod 0600 p2peg.dat`
    $P2PEG->state_file = "/path/to/data/p2peg.dat";

    // Generate a string of random bits
    $random_seed = $P2PEG->generate(true);
    
    // ... use $random_seed as cryptographic salt, seed for PRNG, password generators or anything else that requires unpredictable hight entropy data.
    
    // Generateanothher random string
    $random_seed2 = $P2PEG->generate(true);
    
    // ... and so on

## TODO

To improve the entropy unpredictability, I intend to create system where multiple machines periodically exchange entropy. 
Each pear gets entropy and gives entropy at the same time with a simple GET request like this one:

    curl https://DUzun.Me/entropy/<hash(random_func().$secret)>


