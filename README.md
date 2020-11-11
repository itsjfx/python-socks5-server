# SOCKS5 Server in Python

A multithreaded SOCKS5 server written in Python for Python 3.?+.

A lot of Python SOCKS5 servers I found do not correctly implement [RFC1928](https://tools.ietf.org/html/rfc1928) and [RFC1929](https://tools.ietf.org/html/rfc1929), this project aims to do so.

Codebase is based off https://github.com/rushter/socks5 (with improvements such as better error handling, correct responses, no auth support, IPv6) and is heavily inspired by https://github.com/rofl0r/microsocks for C. Eventually I hope to support all features offered by `microsocks`.

It has been built with goals similar to those of microsocks:
- no artificial limits
- do not aim for minimal binary size, but for minimal source code size, and maximal readability, reusability, and extensibility.

`IPv6` and `Domain name` are untested but *should* be implemented.