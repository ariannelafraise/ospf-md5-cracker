# OSPF MD5 Auth Cracker

A python script to crack **OSPF type 2 cryptographic authentication (MD5) secret keys** from **Wireshark capture files** containing **Hello Packets**. *It would also probably be possible to implement it for all/most packet types.*

## Why it works:
**Authenticated packets have a Auth Crypt Data field containing a MD5 hash**. This hash has been obtained by **concatenating** the **OSPF packet's bytes** with a **secret key**. Normally, all routers know the secret key, so they remake the hash with their secret key; if both match, then it knows that the request is well authenticated. **We can do this same process**, using a wordlist, to **bruteforce** the secret key.

## In action:

Using a sample capture file:
```bash
[arianne@kitaria ospf-md5-cracker]$ python ospf-md5-cracker.py ospf_capture.pcapng ~/wordlists/passwords/rockyou.txt
0201003002020202000000000000000200000a103c7ec8a4fffffffc000a1201000000280c0000020c00000103030303$debe4e93b093ade8a8bc34302c192ced
Bruteforcing with '/home/arianne/wordlists/passwords/rockyou.txt' ...
Key found: minnie14mouse

0201003003030303000000000000000200000a103c7ec8a7fffffffc000a1201000000280c0000020c00000102020202$5445df30fe3d20bf23ecf26c2e531387
Bruteforcing with '/home/arianne/wordlists/passwords/rockyou.txt' ...
Key found: minnie14mouse

0201003002020202000000000000000200000a103c7ec8aefffffffc000a1201000000280c0000020c00000103030303$ed964b2ac353eb6b5431d3251a1d2074
Bruteforcing with '/home/arianne/wordlists/passwords/rockyou.txt' ...
Key found: minnie14mouse

[arianne@kitaria ospf-md5-cracker]$
```

## Usage

1. Install dependencies:
```bash
pip install pyshark
```
2. Launch:
```bash
python ospf-md5-cracker.py <capture>* <wordlist>
```

### Important note
The cracking part of this script is mostly a showcase/fun project. For optimal cracking performance/speed, I strongly recommend using John The Ripper as follows:

1. Launch script without a wordlist and output it to a file:
```bash
python ospf-md5-cracker.py <capture>* > hashes.txt
```
2. Crack with John The Ripper [(net-md5)](https://github.com/openwall/john/blob/bleeding-jumbo/src/net_md5_fmt_plug.c)↗
```bash
john --format=net-md5 --wordlist=~/wordlists/passwords/rockyou.txt hashes.txt
```