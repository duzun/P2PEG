
# Peer to Peer Entropy Generator
@version 0.0.1-alpha

## About

This class uses a combination of system data, client supplied data, some PRNGs available to PHP and timing to generate unpredictable entropy data.

Each pear adds to the entropy, by suppling variable data with the request (in purpos or not) and by the fact of connecting to the server (the exact request time is also accounted).

For connecting pears there is no way to know about internal server state.

For anyone trying to compute the state of the entropy data at a given point in time, or trying to guess


## Usage

    $P2PEG = include "/path/to/lib/P2PEG.php";
    $P2PEG->state_file = "/path/to/data/p2peg.dat"; // optional

    $random_seed = $P2PEG->generate(true);
    
    // ... use $random_seed as cryptographic salt, seed for PRNG or anything else that requires unpredictable entropy data.

## TODO

To improve the entropy unpredictability, I intend to create system where multiple machines periodically exchange entropy. 
Each pear gets entropy and gives entropy at the same time with a simple GET request like this one:

    curl https://DUzun.Me/entropy/<hash(random_func().$secret)>


