# chrome_v80_password_offline

__What is this?__ A couple of python scripts to view saved Chrome and new Edge credentials offline.

__How to use it?__ First run __chrome_dpapi.py__, will ask for the directory that contains 'Local State' and 
'Login Data' (those are on the profile directory of Chrome), it then will ask for the directory that contains
the masterkeys used to encrypt the key (Roaming/Microsoft/Protect/_SID_/).
  You have to supply the login password for that user, if all is well, a _decrypted.bin_ file will be created, just run 
  __chrome_v80_password_offline.py__ and you will see all the credentils saved.
  
__Why two python files?__ Because of licensing issues, chrome_v80_password_offline is a straight copy with a few modifications
  of another repository (1) and that is under the GPL License (as well as this derivated work), the other chrome_dpapi.py depends on
  impacket and a lot of code is just c&p from impacket code, and that is a modified Apache License **
  
  (1) https://github.com/agentzex/chrome_v80_password_grabber/blob/master/chrome_v80_password_grabber.py
  (2) https://github.com/SecureAuthCorp/impacket/blob/master/LICENSE

__What's Offline?__ Most, almost all, of the methods to extract the Chrome saved credentials of a windows machine depends that you run 
them as the user logged in, those scripts just ask windows to decrypt the content with a call to dpapi and that is all. 
But sometimes that is not possible,and you have to extract the credentials, and the machine is not working, hence the _"offline"_
you need to manually extract the needed files and view them it on another machine.

__Requisites__ A lot of python packages, mostly impacket.

__Issues__ 20210419 - At the moment if your user has no password, you can't decrypt the dpapi blob with this script there is another 
way of doing it, not with this script
