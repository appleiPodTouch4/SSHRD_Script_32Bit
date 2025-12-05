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
## Current Bugs
- A6 device can’t pwn
- ...
## Future
- Will update Jailbreak,hacktivation and so on
# History
- commit 1 First commit
- commit 2 Update readme
- commit 3 rm some useless tools,add --device= ,--verion= arg,update readme
- commit 4 Update readme again
- commit 5 add simplify args,update readme
- commit 6 fix sh
- commit 7 update readme
- commit 8 fix a5 pwn，fix some small problems，add patches
- commit 9 add bruteforce password(only support 4-digit password),and fix some bugs 