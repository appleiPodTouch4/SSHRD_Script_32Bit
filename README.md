# SSHRD_Script_32Bit
Forked from [Legacy iOS Kit](https://github.com/LukeZGD/Legacy-iOS-Kit/) 

## Usage
- Clone this repository: `git clone https://github.com/appleiPodTouch4/SSHRD_Script_32Bit --recursive`
- Run `./sshrd32.sh` use default version
## Simplify Args
- 1.`./sshrd32.sh "ios ver/build ver"` use custom version,only support ios verion and ios build version
- 2.`./sshrd32.sh boot` boot ramdisk after make
- 3.`./sshrd32.sh ssh` connect ssh
## Args
- Add `--version=“ramdisk build ver”/“ramdisk ver”` use custom version,only support ios verion and ios build version
- Add `--device="iPhone/iPad/iPodx,x"` custom device_type,without device check
- Add `--menu”` directly access the menu
- Add `--make` make ssh ramdisk only, without boot
- Add `--reboot` reboot device in sshrd
- Add `--password` bruteforce password(only support 4-digit password)
- Add `--bypass` hacktivate device(support iOS7-9.2.X)
- Add `--bypass-part-1` hacktivate device(support iOS9.3-10.3.4)
## Current Bugs
- ...
## Future
- Will update Jailbreak,and so on
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
- commit 12 update readme