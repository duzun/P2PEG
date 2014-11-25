#!/usr/bin/env python
# For testing purposes only 
# DO NOT USE THIS, THIS DOES NOT PROVIDE ENTROPY TO /dev/random, JUST BYTES

# Source: http://unix.stackexchange.com/questions/141197/why-writing-to-dev-random-does-not-make-parallel-reading-from-dev-random-faste

import fcntl
import time
import struct

RNDADDENTROPY=0x40085203

# while True:
    random = "3420348024823049823-984230942049832423l4j2l42j"
    t = struct.pack("ii32s", 8, 32, random)
    with open("/dev/random", mode='wb') as fp:
        # as fp has a method fileno(), you can pass it to ioctl
        res = fcntl.ioctl(fp, RNDADDENTROPY, t)
    time.sleep(0.001)