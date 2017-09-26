### Socks5 proxy
Socks5 proxy server written in one C file. 
Can be used as example how to write your own. 

#### Proto
[Socks5 proto](https://tools.ietf.org/html/rfc1928)

[Socks5 userpass auth proto](https://tools.ietf.org/html/rfc1929)

#### Works on
Every OS which supports POSIX

#### TODO
1. TCP port binding
2. UDP port binding
3. Maybe support for socks4 proto

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
    ./proxy
