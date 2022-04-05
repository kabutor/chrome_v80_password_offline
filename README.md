# chrome_v80_password_offline

__What is this?__ A couple of python scripts to view saved Chrome and new Edge credentials offline.

__How to use it?__ run  __chrome_v80_password_offline.py__ and you 
  will see all the chrome/edge credentials saved.
  
  Program will ask you to the location of the ***Local State***, ***Login Data*** files (you have to copy both to the same directory), the location of the ***Masterkey directory*** (usually under Appdata/Roaming/Microsoft/Protect/<SID>), if the program can infer the SID you don't need to pass it, if not it will ask for it.
 
 Optionally you need to know the user password, or use the nopass option if it's a blank one.  
  
  
__Why two python files?__ On the old version it was because of licensing issues, no is because I plan to reuse chrome_dpapi.py.
 
  chrome_v80_password_offline is a straight copy with some modifications of another repository (1) and that is under the GPL License (as well as this derivated work), the other chrome_dpapi.py depends on dpapick3 ** but it's all my code, so I just move it into the GPL v3.
  
  (1) https://github.com/agentzex/chrome_v80_password_grabber/blob/master/chrome_v80_password_grabber.py
  (2) https://github.com/tijldeneut/DPAPIck3

__What's Offline?__ Most, almost all, of the methods to extract the Chrome saved credentials of a windows machine depends that you run 
them as the user logged in, those scripts just ask windows to decrypt the content with a call to dpapi and that is all. 
But sometimes that is not possible,and you have to extract the credentials, and the machine is not working, hence the _"offline"_
you need to manually extract the needed files and view them it on another machine.

__Bonus.Cookies__
  
  Added a decryptchromecookies.py python script to decrypt the Chrome cookies, file is on the profile Default/Network/Cookies, copy it to the same directory as the Local State and Login Data files, it uses the same method to retrieve the encryption key for the Login Data (is the same) so the requisites are the same
  
__Requisites__ A lot of python packages, mostly dpapick3.


