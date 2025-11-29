#!/bin/bash
clear
update=1       #更新
filecheck=1   #检测文件完整性
local_version=1.1.6
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"  
RED='\033[0;31m'  
GREEN='\033[0;32m'                                           
YELLOW='\033[0;33m'                                          
BLUE='\033[0;34m'
NC='\033[0m'
sshpass=$script_dir/../lib/sshpass
irecovery=$script_dir/../lib/irecovery
iproxy=$script_dir/../lib/iproxy
ipwnder=$script_dir/../lib/ipwnder
idevicerestore=$script_dir/../lib/idevicerestore
futurerestore=$script_dir/../lib/futurerestore
ideviceinfo=$script_dir/../lib/ideviceinfo
dmg=$script_dir/../lib/dmg
activition=$script_dir/../System/iOS7Tethered/activation/activition.py
zenity=$script_dir/../lib/zenity
devicecheck (){
        log "等待设备连接"
        last_mode=""
        while true; do
            usb_info=$(system_profiler SPUSBDataType 2>/dev/null)
            current_mode=""

            if echo "$usb_info" | grep -q ' Apple Mobile Device (DFU Mode)'; then
                current_mode="DFU"
            elif echo "$usb_info" | grep -q ' Apple Mobile Device (Recovery Mode)'; then
                current_mode="恢复"
            elif echo "$usb_info" | grep -q ' iPod'; then
                current_mode="正常"
            fi

            if [[ "$current_mode" != "$last_mode" ]]; then
                if [[ -n "$current_mode" ]]; then
                    echo -e "\r设备已进入 ${current_mode} 模式     "  # 用空格覆盖旧内容
                else
                    echo -ne "\r等待设备连接...\033[K"  # \033[K 清除行尾
                fi
                last_mode="$current_mode"
            fi

            if [[ -n "$current_mode" ]]; then
                break  # 检测到模式后退出循环
            fi

            sleep 1  # 降低检测频率，减少 CPU 占用
        done   
}

deviceinfo (){
devicecheck    
while true; do
    if [ "$current_mode" = "DFU" ]; then
        device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
        if [[ -n $device_pwnd ]]; then
            pwd=是
        else
            pwn=否
        fi
       os=不检测
       mod=$($irecovery -q | grep -i "product" | awk -F': ' '{print $2}')
       ecid=$($idevicerestore -l 2>/dev/null | grep -i "ECID" | awk '{print $3}')
       break
    elif [ "$current_mode" = "恢复" ]; then
       os=不检测
       mod=$($irecovery -q | grep -i "product" | awk -F': ' '{print $2}')
       break
    else
        if nc -zv 127.0.0.1 6414 &>/dev/null; then
            # 检测 SSH 是否可连接
            if $sshpass -p alpine ssh -p 6414 -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@127.0.0.1 "echo 'SSH 连接成功'" &>/dev/null; then
                current_mode=SSHRD
                os=不检测
                mod=不检测
            else
                current_mode=正常
                os=$($ideviceinfo -k ProductVersion)
                mod=$($ideviceinfo -k ProductType)
                ecid=$($ideviceinfo -s -k UniqueChipID)
            fi
        else
            current_mode=正常
            os=$($ideviceinfo -k ProductVersion)
            mod=$($ideviceinfo -k ProductType)
            ecid=$($ideviceinfo -s -k UniqueChipID)
        fi
       break
    fi
done    
}

t4_6.x() {
                DFUhelper pwn
                log 发送iBSS
                $irecovery -f $script_dir/bin/SSHRD/6.1.6/iBSS
                sleep 2
                log 发送iBEC
                $irecovery -f $script_dir/bin/SSHRD/6.1.6/iBEC
                sleep 3
                log 发送Ramdisk
                $irecovery -f $script_dir/bin/SSHRD/6.1.6/Ramdisk.dmg
                $irecovery -c "ramdisk"
                sleep 2
                log 发送devicetree
                $irecovery -f $script_dir/bin/SSHRD/6.1.6/DeviceTree.dec
                $irecovery -c "devicetree"
                sleep 1
                log 发送Kernelcache
                $irecovery -f $script_dir/bin/SSHRD/6.1.6/Kernelcache.dec
                $irecovery -c "bootx"
                log "等待设备启动(约10秒)..."
                sleep 10
                log "设置SSH端口(6414)"
                pkill -9 -f "iproxy.*6414" 2>/dev/null
                $iproxy 6414 22 -s 127.0.0.1 >/dev/null &
                read -p 回车开始越狱
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "mount.sh root"
                $sshpass -p alpine scp -v -P 6414 -o StrictHostKeyChecking=no $script_dir/bin/Jailbreak/p0sixspwn.tar root@127.0.0.1:/mnt1
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "mount.sh pv"
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "cd /mnt1; tar -xvf p0sixspwn.tar"
                $sshpass -p alpine scp -v -P 6414 -o StrictHostKeyChecking=no $script_dir/bin/Jailbreak/fstab_rw.tar root@127.0.0.1:/mnt1
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "cd /mnt1; tar -xvf fstab_rw.tar"
                $sshpass -p alpine scp -v -P 6414 -o StrictHostKeyChecking=no $script_dir/bin/Jailbreak/freeze.tar root@127.0.0.1:/mnt1/private/var
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "tar -xvf /mnt1/private/var/freeze.tar -C /mnt1"
                $sshpass -p alpine scp -v -P 6414 -o StrictHostKeyChecking=no $script_dir/bin/Jailbreak/sshdeb.tar root@127.0.0.1:/mnt1
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "cd /mnt1; tar -xvf sshdeb.tar" 
                log 是否直接激活设备
                read -p "是否继续执行？(yes/no) [默认: yes]: " user_input
                user_input=${user_input:-yes}
                user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')
                if [[ "$user_input" == "yes" || "$user_input" == "y" ]]; then
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "rm -rf /mnt1/usr/libexec/lockdownd"
                $sshpass -p alpine scp -v -P 6414 -o StrictHostKeyChecking=no $script_dir/bin/Others/lockdownd root@127.0.0.1:/mnt1/usr/libexec
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "chmod 755 /mnt1/usr/libexec/lockdownd"
            else 
                log 跳过激活 
            fi           
                $sshpass -p alpine ssh -p 6414 root@127.0.0.1 -o StrictHostKeyChecking=no "reboot_bak"
}
