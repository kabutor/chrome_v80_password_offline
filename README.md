# chrome_v80_password_offline

__What is this?__ A couple of python scripts to view saved Chrome and new Edge credentials offline.

__How to use it?__ First run chrome_dpapi.py, will ask for the directory that contains 'Local State' and 
'Login Data' (those are on the profile directory of Chrome), it then will ask for the directory that contains
the masterkeys used to encrypt the key (Roaming/Microsoft/Protect/<SID>/).
  You have to supply the login password for that user, if all is well, a decryted.bin file will be created, just run 
  chrome_v80_password_offline.py and you will see all the credentils saved.
  
__Why two python files?__ Because of licensing issues, chrome_v80_password_offline is a straight copy with a few modifications
  of another repository (1) and that is under the GPL License (as well as this derivated work), the other chrome_dpapi.py depends on
  impacket and a lot of code is just c&p from impacket code, and that is a modified Apache License **
  (1) https://github.com/agentzex/chrome_v80_password_grabber/blob/master/chrome_v80_password_grabber.py
  (2) https://github.com/SecureAuthCorp/impacket/blob/master/LICENSE

__Issues__ 20210419 - At the moment if your user has no password, you can't decrypt the dpapi blob with this script there is another 
way of doing it, not with this script
