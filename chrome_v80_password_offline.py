#!/usr/bin/python3

import os
import json
import base64
import sqlite3
from Cryptodome.Cipher import AES


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
        # print("Probably saved password from Chrome version older than v80\n")
        # print(str(e))
        return "Chrome < 80"



if __name__ == '__main__':

    master_key = get_master_key()
    login_db = 'Login Data'
    conn = sqlite3.connect(login_db)
    cursor = conn.cursor()

    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
    for r in cursor.fetchall():
        url = r[0]
        username = r[1]
        encrypted_password = r[2]
        decrypted_password = decrypt_password(encrypted_password, master_key)
        print("URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n")

    cursor.close()
    conn.close()
