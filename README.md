This is a for fun project I wrote to perform basic encryption on any file you give it.
It is not designed with very large files in mind, so I'm not sure how well it will work for that.
For small files, say < 1MB, its bassically instant.


This is not intended to be used as a genuine encryption algorithm.  I am not qualified to make claims
about the level of cryptographic security of this program, but I imagine its not up to the standard.
That being said, the source of random numbers used to encrypt the given file is derived from my own 
implementation of SHA-256, which is a genuine secure hash algorithm.  

#### Compile on linux with:
``` 
gcc -O2 *.c -o main
```

#### Algorithm
- There are 8 distinct steps of encryption in this algorithm.  Each one contains several functions for scrambling the input bytes in some way.
- The first function of each step is a bitwise rotate function.  It scans through the bytes one at a time, performing bitwise rotates on integers of varying width derived from the input bytes.  A bitwise rotate is a bit shift where the bits that would normally be pushed off the end get wrapped around to the other side. 
- The second function of each step is a simple permutation of the bytes.  The permutation operates on chunks of bytes of varying size, depending on the step number.
- The final function of each step is a xor, which is performed 32 bits at a time accoss the entire input.

This algorithm is very sensitive to the order of the functions.  In a more strightforward encryption algorithm that just uses repeated xor opperations, the opperations can be reversed in any order since xor is commutitave.  However, sensitivity to order does very little for actual cryptographic security, and is mostly redundant.  I did it just because it was fun to make.

### Scavenger Hunt!
Included in this repo is a file "reward.enc".  This is a file encrypted using this very enryption program.  
The first person to decrypt it will get a reward of 10,000 $'s.  All the information needed to decrypt reward.enc and archive.enc is in this repo.  
You do not need any external knowledge or tools of any kind.  In order to decrypt reward.enc, you will first need to decrypt archive.enc as that will contain the 
key to decrypting reward.enc.  Good luck, and happy hunting!

Progress: No one has solved it yet.
