#!/usr/bin/python3

import os
import json
import base64
import sqlite3
from Cryptodome.Cipher import AES
import chrome_dpapi
import argparse
import sys

def get_master_key():
    f= open("decrypted.bin","rb")
    master_key=f.read()
    f.close()
    return master_key


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
        return decrypted_pass
    except Exception as e:
        # print(str(e))
        return "Credentials extraction error maybe enc_key is wrong or Chrome version < 80"




if __name__ == '__main__':
	# arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir","-d",default='./', help="directory where Local State and Login Data is located")
    parser.add_argument("--masterkey", "-m", help="set masterkey directory")
    parser.add_argument("--sid", "-s",  help="set SID(optional)")
    parser.add_argument("--password", "-p", help="user password")
    parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
    parser.add_argument("--config","-c",dest="config_reg",help="Register files location (Usually \Windows\System32\config")
    parser.add_argument("--tba","-t", dest="tba", action='store_true', help="if TBA, use DPAPI key")
    parser.set_defaults(nopass=False)
    parser.set_defaults(tba=False)
    #parser.set_defaults(sid=None)
    args = parser.parse_args()

    #init external class to decrypt enc_key
    ret = chrome_dpapi.Dpapi_decrypt(args.dir,args.masterkey,args.password,args.sid, args.nopass, args.tba, args.config_reg)
    ret.main()
    # Get key
    enc_key = ret.return_key()
    if (enc_key == ''):
        print("Error getting encription key")
        sys.exit()

    login_db = os.path.join(args.dir,'Default','Login Data')
    conn = sqlite3.connect(login_db)
    cursor = conn.cursor()

    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
    for r in cursor.fetchall():
        url = r[0]
        username = r[1]
        encrypted_password = r[2]
        decrypted_password = decrypt_password(encrypted_password, enc_key)
        print("*" * 50)
        print("URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" )

    cursor.close()
    conn.close()
