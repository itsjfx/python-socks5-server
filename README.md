# SOCKS5 Server in Python

A multithreaded SOCKS5 server written in Python for Python 3.?+.

Codebase is based off https://github.com/rushter/socks5 (with improvements such as better error handling, correct responses, no auth support, IPv6) and highly inspired by https://github.com/rofl0r/microsocks for C. Eventually I hope to support all features offered by `microsocks`.

`IPv6` and `Domain name` are highly untested but *should* be implemented.