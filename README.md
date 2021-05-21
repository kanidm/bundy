Bundy
=====

Bundy is a small library that allows verification and signatures of parcels of data. Unlike
[fernet](https://github.com/fernet/spec) which encrypts and creates opaque blobs, Bundy
allows a client to inspect and see the data. It is transparent, and should NOT be used to
store secrets.

Use cases are:

* Signing cookies or tokens that a client should be able to read and parse, but not alter.
* In place of JWT, but without many of the complications and issues that come with JWT.

Why is this named Bundy?
------------------------

Fernet is named after an [Italian spirit](https://en.wikipedia.org/wiki/Fernet) - Bundy is named after an [Australian spirit](https://en.wikipedia.org/wiki/Bundaberg_Rum).


