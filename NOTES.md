wslib
=====

general

* If in case of client errors the WSConnection class throws
exceptions (mainly regarding handshake issues) - a valid 
HTTP 400 (or similar) must be returned to the client. As this
is defined in the protocol, it is one of the libraries tasks.
** May get resolved if WSConnection is no longer used stand alone
but got incorporated in wslib.Serve or similar.


open questions

* should the http request class be removed? Would be a performance
gain but handling the first request may become more difficult.

* should the asynchat module be used instead of asyncore or should
all functionality be written "vanilla"?