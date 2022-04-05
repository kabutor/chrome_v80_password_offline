# Based on:
# https://gist.github.com/GramThanos/ff2c42bb961b68e7cc197d6685e06f10
import os
import json
import base64
import sqlite3
import argparse

# python.exe -m pip install pycryptodomex
from Cryptodome.Cipher import AES
import chrome_dpapi



enc_key = None

# arguments
parser = argparse.ArgumentParser()
parser.add_argument("--dir","-d",default='./', help="directory where Local State and Login Data is located")
parser.add_argument("--masterkey", "-m", help="set masterkey directory")
parser.add_argument("--sid", "-s",  help="set SID(optional)")
parser.add_argument("--password", "-p", help="user password")
parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
parser.set_defaults(nopass=False)
#parser.set_defaults(sid=None)
args = parser.parse_args()

#init external class to decrypt enc_key
ret = chrome_dpapi.Dpapi_decrypt(args.dir,args.masterkey,args.password,args.sid, args.nopass)
ret.main()
# Get key
enc_key = ret.return_key()
if (enc_key == ''):
	print("Error getting encription key")
	sys.exit()

# Connect to the Database
conn = sqlite3.connect(os.path.join(args.dir, 'Cookies'))
cursor = conn.cursor()

# Get the results
cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
for host_key, name, value, encrypted_value in cursor.fetchall():
	# Decrypt the encrypted_value
	try:
		# Try to decrypt as AES (2020 method)
		cipher = AES.new(enc_key, AES.MODE_GCM, nonce=encrypted_value[3:3+12])
		decrypted_value = cipher.decrypt_and_verify(encrypted_value[3+12:-16], encrypted_value[-16:])
	except:
		# If failed try with the old method
		decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8') or value or 0

	# Update the cookies with the decrypted value
	# This also makes all session cookies persistent
	cursor.execute('\
		UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0\
		WHERE host_key = ?\
		AND name = ?',
		(decrypted_value, host_key, name));

conn.commit()
conn.close()
