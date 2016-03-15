
# Conspire

Conspire is a tool for setting up and managing Conspiracies.

It uses PGP/GPG keyrings to encrypts sets of secrets in a special
directory, called a vault. Each keyring is a group of users who are set up
as shared recepients for a secret file, which is stored in the vault.

## Requirements

* You must have a PGP or GnuPG secret key and public key.
* Ideally you should have one or more friend's public key, so you can
  conspire with them.

## Getting Started

The first step is to get a secret and private key set up. The full scope of
selecting and using PGP or GnuPG is beyond the scope of this tool but you
can find plenty of information on how to get the software and use it at
(http://www.gnupg.org)[the GnuPG website].

### I'm Too Lazy, Show Me Anyway

The basic thing is to set up a new key ...

```
$ gpg --gen-key
gpg (GnuPG) 1.4.20; Copyright (C) 2015 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
Your selection? 1
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 
Key does not expire at all
Is this correct? (y/N) y

You need a user ID to identify your key; the software constructs the user
ID
from the Real Name, Comment and Email Address in this form:
    "Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>"

Real name: Sherlock Holmes
Email address: sherlock.holmes@bakerstreet.co.uk
Comment: Detective
You selected this USER-ID:
    "Sherlock Holmes (Detective) <sherlock.holmes@bakerstreet.co.uk"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
You need a Passphrase to protect your secret key.

We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
...+++++
......+++++
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
.+++++
...+++++
gpg: key EAEA1BB3 marked as ultimately trusted
public and secret key created and signed.

gpg: checking the trustdb
gpg: 3 marginal(s) needed, 1 complete(s) needed, PGP trust model
gpg: depth: 0  valid:   3  signed:   2  trust: 0-, 0q, 0n, 0m, 0f, 3u
gpg: depth: 1  valid:   2  signed:   8  trust: 2-, 0q, 0n, 0m, 0f, 0u
gpg: next trustdb check due at 2017-05-15
pub   4096R/EA65FCB3 2016-03-13
      Key fingerprint = 2DEF BFA8 7C44 616D 4B79  2505 9BA5 AB42 EA65 FCB3
uid                  Sherlock Holmes (Detective) <sherlock.holmes@bakerst>
sub   4096R/47645C58 2016-03-13

```

It will be a smart thing if you edit your key qith ``gpg --edit-key`` to add
trust, signatures, and cross-certification.

### Creating a default group



```
gpg -a --output vault/default --export 02D5698AD6BE2EB0 --export 4ABE7D9A80CC940B
```


