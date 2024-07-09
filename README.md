# AES-Blake

This is a working example of the AES cipher, where the original key scheduling algorithm has been replaced with the Blake hashing function.
The AES-Blake cipher supports [Authenticated Encryption with Associated Data](https://en.wikipedia.org/wiki/Authenticated_encryption) and **256**, **384** or **512** bit wide internal state, 
offering the equivalent amount of cryptographic security. The formal security proof and the implementation in the C language are works in progress.
