### Socks proxy
Socks proxy server written in one C file. 
Supports socks4, socks4a and socks5 protocols without binding and udp stuff. 
Can be used as example how to write your own. 

#### Build status and CI pipeline link
[![Build Status](https://travis-ci.org/fgssfgss/socks_proxy.svg?branch=master)](https://travis-ci.org/fgssfgss/socks_proxy)

#### Proto
[Socks5 proto](https://tools.ietf.org/html/rfc1928)

[Socks5 userpass auth proto](https://tools.ietf.org/html/rfc1929)

[Socks4 proto](https://www.openssh.com/txt/socks4.protocol)

[Socks4a proto](https://www.openssh.com/txt/socks4a.protocol)

#### Works on
Every OS which supports POSIX

#### TODO
1. TCP port binding
2. UDP port binding

#### Usage
[-h]		- *print usage*

[-n PORT]	- *set port to listen*

[-a AUTHTYPE]	- *set authtype: 0 for NOAUTH, 2 for USERPASS*

[-u USERNAME]	- *set username for userpass authtype*

[-p PASSWORD]	- *set password for userpass authtype*

[-l LOGFILE]	- *set file for logging output*

#### Build and run
No additional requirements, only compiler or crosscompiler needed

    make
    make test
    ./proxy
