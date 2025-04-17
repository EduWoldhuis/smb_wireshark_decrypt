### A python3 tool to get the necessary information to decrypt SMB3 from a PCAP file.
Note: the user password or NTLM hash is required for decryption.

This script is modified from https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2, to add a lot more functionality.
requirements: Tshark, python3

I created this script to solve https://tryhackme.com/room/blockroom.
example commmand:
```
┌─[root@edu-virtualbox]─[/home/edu/THM/block]
└──╼ #python3 smbdecrypt.py -i traffic.pcapng -x 1 -v --ntlm 3f29138a04aadc19214e9c04028bf381
USER WORK: b'E\x00S\x00H\x00E\x00L\x00L\x00S\x00T\x00R\x00O\x00P\x00W\x00O\x00R\x00K\x00G\x00R\x00O\x00U\x00P\x00'
PASS HASH: 3f29138a04aadc19214e9c04028bf381
RESP NT:   f48087e449d58b400e283a27914209b9
NT PROOF:  0ca6227a4f00b9654a48908c4801a0ac
KeyExKey:  9754d7acae384644b196c05cda5315df
Random SK: facfbdf010d00aa2574c7c41201099e8
Session ID: 4500000000100000
```
