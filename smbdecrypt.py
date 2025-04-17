import hashlib
import hmac
import argparse
import binascii
import subprocess


# stolen from impacket. Thank you all for your wonderful contributions to the community
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    print("Warning: You don't have any crypto installed. You need pycryptodomex")
    print("See https://pypi.org/project/pycryptodomex/")
    exit(1)

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    sessionKey = cipher.encrypt(exportedSessionKey)
    return sessionKey

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-i", "--input", required=False, help="Input PCAP or PCAPNG file")
parser.add_argument("-x", required=False, help="If there are multiple different encrypted SMB conversations in one file, the selection.")
parser.add_argument("--ntlm", required=False, help="The NTLM hash of the user.")
parser.add_argument("-u", "--user", required=False, help="User name")
parser.add_argument("-d", "--domain", required=False, help="Domain name")
parser.add_argument("-p", "--password", required=False, help="Password of User")
parser.add_argument("-n", "--ntproofstr", required=False, help="NTProofStr. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-k", "--key", required=False, help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

args = parser.parse_args()

if args.input:
    output = subprocess.run(['tshark', '-r', args.input, '-Y', 'ntlmssp.ntlmv2_response.ntproofstr', '-T', 'fields', '-e', 'ntlmssp.auth.domain', '-e', 'ntlmssp.auth.username', '-e', 'ntlmssp.ntlmv2_response.ntproofstr', '-e', 'ntlmssp.auth.sesskey', '-e', 'smb2.sesid'], capture_output=True, text=True).stdout.split('\n')
    if args.x:
        output = output[int(args.x)].split('\t')
    else:
        output = output[0].split('\t')

if args.input: 
    # Upper Case User and Domain
    domain = output[0].upper().encode('utf-16le')
    user = output[1].upper().encode('utf-16le')
else:
    user = args.user.upper().encode('utf-16le')
    domain = args.domain.upper().encode('utf-16le')

if args.ntlm:
    password = bytes.fromhex(args.ntlm)
else:
    # Create 'NTLM' Hash of password
    passw = args.password.encode('utf-16le')
    hash1 = hashlib.new('md4', passw)
    password = hash1.digest()


# Calculate the ResponseNTKey
h = hmac.new(password, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

# Use NTProofSTR and ResponseNTKey to calculate Key Exchange Key
if args.input:
    NTproofStr = binascii.unhexlify(output[2])
else:
    NTproofStr = binascii.unhexlify(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

# Decrypt Encrypted Session Key with Key Exchange Key via RC4
if args.input:
    encryptedSessionKey = binascii.unhexlify(output[3])
else:
    encryptedSessionKey = binascii.unhexlify(args.key)
RsessKey = generateEncryptedSessionKey(KeyExchKey, encryptedSessionKey)

if args.verbose:
    print("USER WORK: {}".format(user + domain))
    print("PASS HASH: {}".format(binascii.hexlify(password).decode()))
    print("RESP NT:   {}".format(binascii.hexlify(respNTKey).decode()))
    print("NT PROOF:  {}".format(binascii.hexlify(NTproofStr).decode()))
    print("KeyExKey:  {}".format(binascii.hexlify(KeyExchKey).decode()))

print("Random SK: {}".format(binascii.hexlify(RsessKey).decode()))
if args.input:
    # remove the 0x beforehand to enable copy pasting, and reverse the endianness.
    ba = bytearray.fromhex(output[4][2:])
    ba.reverse()
    print("Session ID: {}".format(ba.hex()))
