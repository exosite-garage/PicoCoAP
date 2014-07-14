PicoCoAP is a very minimal CoAP library written in C. The main goal of this
library is to implement the CoAP protocol while using a little memory as
possible.

# Values

1. Safety
  * Above all, this library aims to be safe. All memory operations are done with
    explicitly stated bounds. In the event of a malformed packet it should fail
    safely.
2. Completeness
  * This is intended to be a complete implementation of the protocol and tries not
    to make simplifications that are "usually" safe to make.
3. Memory Usage
  * All operations try to use the absolute minimum amount of memory possible,
    while not violating the first two values, even at the expense of processing
    time. All operations are done on a buffers containing the actual message
    network binary representation for each method call.
4. Simple API
  * This library should be able to be used by users who only have a basic
    understanding of the protocol. Terminology is intended to be simple, but
    does not invent new terms that the RFC already defines.

# Status

Currently only message encoding and decoding is currently implemented. I will be
looking into creating a server that handles the actual sending and receiving of
messages along with the associated retries and other protocol complexity. This
may or may not ever be added.

As this is a new library there may be bugs, please report them. The best way is
to open a pull request with a test case that shows the bug and better yet also a
patch to fix it. Additionally, general comments about design and usability are
also welcome.