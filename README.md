# Public Key Recovery

## PKR Intro

When messages are signed with a private key (ECDSA) and need to be checked with the explicit knowledge
of the related public key, PKR is a trick which allows the recovery of the the public key from
the hash (SHA-256) of the message and its signature (ECDSA).  
Standalone code "extracted" from https://bitcoinj.github.io/

