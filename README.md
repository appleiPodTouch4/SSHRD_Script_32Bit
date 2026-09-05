# SSHRD_Script_32Bit
Forked from [Legacy iOS Kit](https://github.com/LukeZGD/Legacy-iOS-Kit/) Add some custom functions

## Usage
- Clone this repository: `git clone https://github.com/appleiPodTouch4/SSHRD_Script_32Bit --recursive`
- Run `./sshrd32.sh` or `.\sshrd32.bat` use default version
- Run `./sshrd32.sh` or `.\sshrd32.bat` + iOS version/build id + Main args + Other args
## Main Args
- 1.`./sshrd32.sh "ios ver/build ver"` use custom version,only support ios verion and ios build version
- 2.`./sshrd32.sh boot` boot ramdisk after make
- 3.`./sshrd32.sh reboot` reboot device
- 4.`./sshrd32.sh ssh` connect ssh
- 5.`./sshrd32.sh menu` go to main menu
- 6.`./sshrd32.sh get-ios-ver` Get device iOS version
- 7.`./sshrd32.sh dump-blobs` Dump shsh blobs
- 8.`./sshrd32.sh dump-raws` Dump raws
- 9.`./sshrd32.sh jailbreak` Jailbreak device(support iOS4-iOS9.3.4) only Untethered
- 10.`./sshrd32.sh password` Unlimite try password
- 11.`./sshrd32.sh hactivate` Hactivate device(Support iOS4-10)
- 12.`./sshrd32.sh hactivate-part-2` The next step for hacktivate on iOS 9.3+
- 13.`./sshrd32.sh update` Update this script
- 14.`./sshrd32.sh help` Show script help
## Other Args
- Add `--version=“ramdisk build ver”/“ramdisk ver”` use custom version,only support ios verion and ios build version
- Add `--device="iPhone/iPad/iPodx,x"` custom device_type,without device check
- Add `--ipsw”` Use local ipsw instead download
- Add `--no-device` Make ramdisk without device
- Add `--debug` Run script with set -x
- Add `--irec` Check device using irecovery
## Current Bugs
-   Windows version is in VERY early stages of development,waiting for update
## Future
- ...
# History
- commit 1 initial commit
- commit 2 First commit
- commit 3 Update readme
- commit 4 rm some useless tools,add --device= ,--verion= arg,update readme
- commit 5 Update readme again
- commit 6 add simplify args,update readme
- commit 7 fix sh
- commit 8 update readme
- commit 9 fix a5 pwn，fix some small problems，add patches
- commit 10 add bruteforce password(only support 4-digit password),and fix some bugs 
- commit 11 update readme
- commit 12 update hacktivate part,fix some bugs
- commit 13 update readme
- commit 14 add unblock screen lock limit,fix some bugs
- commit 15 add jailbreak device part,update readme
- commit 16 try to add update
- commit 17 fix update
- commit 18 update readme
- commit 19 fix legacy part
- commit 20 fix legacy part
- commit 21 update readme
- commit 22 fix bruteforce and some bugs
- commit 23 update readme
- commit 24 fix linux part,remove justboot part(it is useless),and fix some bugs
- commit 25 add windows bins,add sshrd.bat
- commit 26 add sshrd32.bat
- commit 27 fix
- commit 28 fix sshrd32.bat
- commit 29 rewrite the main logic of sshrd32.sh,rewrite readme
- commit 30 fix bruteforce part,update .gitignore
- commit 31 fix jailbreak for windows
- commit 32 rm useless files
- commit 33 sync the newest leagacy ios kit and fix s5l8900 device boot issue
- commit 34 update readme and fix some bugs