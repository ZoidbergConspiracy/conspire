
# Conspire

Conspire is a tool for setting up and managing Conspiracies.

It uses PGP/GPG keyrings to encrypts sets of secrets in a special
directory, called a vault. Each keyring is a group of users who are set up
as shared recepients for a secret file, which is stored in the vault.

Sharing secrets among groups of people with GPG is a little awkward, because
there is no facility to manage groups. This tool aims to make it simpler
to manage secrets among groups.

## Requirements

* You must have a PGP or GnuPG secret key and public key.
* Ideally you should have one or more friend's public key, so you can
  conspire with them.
* An editor, specified with the EDITOR environment variable.
* - Right now it is known to work on Linux and Mac. Not tested on Windows.

## Design and Security

The tool is written in pure Go, and this helps minimize some comon stupid
programming errors that can lead to security issues, but the tool still needs
a rigorous security review.

It does rely heavily on the existence of GPG managed keychains, and it will also
try to use the GPGAgent to retrieve passphrases on keys, where available. Again,
this needs some work to get it more secure.

Finally, it also does call out to an external editor, and this process involves
creating temporary files in the vault directory to allow standard editors to
operate on unencrypted secrets. There are still problems handing off to some
editors, and those temporary files may hang around (but the tool will try to
tell you if this happens), but you should make sure you trust your editor, your
console, and your vault directory.

## Getting Started

1. The first step is to get a secret and private key set up. The full scope of
  selecting and using PGP or GnuPG is beyond the scope of this tool but you
  can find plenty of information on how to get the software and use it at
  [http://www.gnupg.org]([the GnuPG website).

2. Next, you need to get and trust some keys of some co-conspirators. You should
  Get their public keys and add them to your GPG keychain and trust them. The
  conspire tool uses long KeyIDs from GPG to uniquely identify your trusted
  co-conspirators, so you should consider adding ```keyid-format LONG``` to your
  ```gpg.conf``` file.

3. Install the conspire tool, which should be as simple as ...
   ```
go get -u github.com/ZodbergConspiracy/conspire
  ```
4. Identify where you want to manage your first vault. You can have multiple vaults.
  Vaults are just directories with group and secret files. You can identify your
  vault directory with the ```CONSPIRACY_VAULT``` environment variable, or using
  the ```--directory``` command flag.

5. Add a default group to your local vault.

6. Pick an editor, and set the path to your editor via the ```EDITOR``` environment
  variable.

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


