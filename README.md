# pyzrtp

Pythonic implementation of ZRTP (rfc 6189), and SRTP (rfc 3711).

## Features

It is based on Python3, focused on protocol tampering and easy reuse.

Submodules in zrtp directory wrap cryptographic modules.
Note that Skein, TwoFish, Elliptic Curves are not supported (yet).
A submodule implements ZRTP parsing and unparsing.

It has sufficient flexibility to build a ZRTP "man-in-the-middle" attack,
targetting weak implementations that do not check hvi value present in Commit message.

## Dependencies

AES cipher is brought by [PyCrypto] (https://www.dlitz.net/software/pycrypto/).

## Sample ZRTP endpoint

`endpt.py` implements a cacheless passive ZRTP agent. It does not support multistream mode nor preshared mode.
Agent is based on asyncio, to ease embedding into a larger SIP / websocket signalling program.

## SRTP usage

`srtp.py` contains a Context class, which derives keystreams for common labels.
Context class contains srtp_protect and srtp_unprotect methods.
Both expect data at RTP level, i.e. including RTP header.

As an example, srtp-decrypt.py can be used to decrypt an SRTP capture.
provided you are able to give the SDES material.
A Pythonic version of srtp-decrypt is also present, so you can check srtp.Context usage.
To decipher the sample trace, use the command line:

```
./srtp-decrypt.py | text2pcap -t "%H:%M:%S." -u 10000,10000 - - > marseillaise-rtp.pcap
```

It will create a pcap containing unprotected RTP packets which can be listen using Wireshark features.

Some implementations use SRTP to transport custom data using custom labels.
It is left as an exercise for the readers to implement such usage.


