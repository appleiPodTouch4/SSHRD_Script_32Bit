#!/bin/bash
script_dir=".."
tmp="."
saved="../saved"
ssh_port=2222
isoscheck=1
jelbrek=../resources/Jailbreak
script_path=$(dirname "$0")/$(basename "$0")

if [[ "$debug" == "1" ]]; then
    menu_old=1
    set -x
fi

log() {
    GREEN='\033[32m'
    RESET='\033[0m'
    echo -e "${GREEN}[Log]${RESET} ${GREEN}$@${RESET}" > /dev/tty
    eval "$@" >/dev/null 2>&1
}

error() {
    RED='\033[31m'
    RESET='\033[0m'
    echo -e "${RED}[ERROR]${RESET} ${RED}$@${RESET}" > /dev/tty
    eval "$@" >/dev/null 2>&1
}

warning() {
    YELLOW='\033[33m'
    RESET='\033[0m'
    echo -e "${YELLOW}[WARNING]${RESET} ${YELLOW}$@${RESET}" > /dev/tty
    eval "$@" >/dev/null 2>&1
}

debug() {
    local BLUE='\033[38;5;45m'
    RESET='\033[0m'
    echo -e "${BLUE}[DEBUG]${RESET} ${BLUE}$@${RESET}" > /dev/tty
    eval "$@" >/dev/null 2>&1
}

tip() {
    local PURPLE='\033[0;35m'
    local NC='\033[0m'
    echo -e "${PURPLE}$1${NC}"
}

print() {
    local PURPLE='\033[0;35m'
    local NC='\033[0m'
    echo -e "${PURPLE}$1${NC}"
}

input() {
    YELLOW='\033[33m'
    RESET='\033[0m'
    echo -e "${YELLOW}[Input]${RESET} ${YELLOW}$@${RESET}" > /dev/tty
    eval "$@" >/dev/null 2>&1
}

pause() {
    if [ -z "$@" ]; then
        input "Press Enter/Return to continue (or press Ctrl+C to cancel)"
    else
        input "$@ (or press Ctrl+C to cancel)"
    fi
    read -s
}

oscheck() {
    arch_path=
    if [[ "$isoscheck" == "1" ]]; then
        platform_check=$(uname)
        arch_check=$(uname -m)
        if [[ "$platform_check" == "Darwin" ]]; then
            platform=macos
            if [[ "$arch_check" == "x86_64" ]]; then
                platform_arch=x86_64
            elif [[ "$arch_check" == "arm64" ]]; then
                platform_arch=arm64
            else
                error Unsupport platform,please use support platform
                exit
            fi
        elif [[ "$platform_check" == "Linux" ]]; then
            platform=linux
            if [[ "$arch_check" == "x86_64" ]]; then
                platform_arch=x86_64
            elif [[ "$arch_check" == "arm64" ]]; then
                platform_arch=arm64
            else
                error Unsupport platform,please use support platform
                exit
            fi
        else
            error Unsupport platform,please use support platform
            exit
        fi
        if [[ "$platform" == "macos" ]]; then
            if [[ "$platform_arch" == "arm64" ]]; then
                if [[ "$ship_platform_check" != "1" ]]; then
                    warning "Using M-series chips may cause compatibility issues; please use with caution."
                    pause Press Enter to ignore this issue.  
                fi
                dir="../bin/macos/arm64"
            else
                dir="../bin/macos"
            fi
            macos_ver="${1:-$(sw_vers -productVersion)}"
            macos_major_ver="${macos_ver:0:2}"
            if [[ $macos_major_ver == 10 ]]; then
                macos_minor_ver=${macos_ver:3}
                macos_minor_ver=${macos_minor_ver%.*}
                if (( macos_minor_ver < 11 )); then
                    if [[ "$ship_platform_check" != "1" ]]; then
                        error "Your macOS version is too old. Please upgrade to macOS High Sierra or later."
                        exit
                    fi
                fi
                case $macos_minor_ver in
                    #11 ) macos_name="El Capitan";; too old
                    #12 ) macos_name="Sierra";; too old
                    13 ) macos_name="High Sierra";;
                    14 ) macos_name="Mojave";;
                    15 ) macos_name="Catalina";;
                esac
            fi
            case $macos_major_ver in
                11 ) macos_name="Big Sur";;
                12 ) macos_name="Monterey";;
                13 ) macos_name="Ventura";;
                14 ) macos_name="Sonoma";;
                15 ) macos_name="Sequoia";;
                26 ) macos_name="Tahoe";;
            esac
            if (( macos_major_ver > 12 )); then
                warning "There may be compatibility issues when using devices running macOS Monterey or later. Do you want to continue?"
                yesno continue?
                 if [[ $? == 1 ]]; then
                    :
                else
                    exit
                fi
            fi
            platform_message="macOS ${macos_name}($platform_arch)"
        elif [[ "$platform" == "linux" ]]; then
            warning The Linux version is still being adapted, and some features have not yet been fixed. Should we continue using it?
            pause Press Enter to continue.
            check_sudo
            install_depends
            arch_path="linux/"
            linux_name=$(grep '^NAME=' /etc/os-release | cut -d'"' -f2)
            platform_message="${linux_name} ($platform_arch)"
            dir="../bin/linux"
        fi
    fi

}

check_sudo() {
    if [ -z "$SUDO_USER" ]; then
        log "Please enter your password."
        if sudo -v >/dev/null 2>&1; then
            clear
            return 0
        else
            error "Unable to obtain sudo privileges"
            exit 1
        fi
    else
        clear
        return 0
    fi
}

set_path() {
    if [[ "$script_dir/" =~ [[:space:]] ]]; then
        error "Directory path contains whitespace characters！" >&2
        error "Current directory: '$script_dir'" >&2
        pause Press enter to exit
        exit 1
    fi
    chmod +x $dir/*
    if [[ "$platform" == "macos" ]]; then
        sshpass=""
        irecovery=""
        iproxy=""
        ipwnder=""
        idevicerestore=""
        futurerestore=""
        futurerestore_old=""
        ideviceinfo=""
        dmg=""
        zenity="$dir/zenity"
        ideviceactivation=""
        ideviceinstaller=""
        primepwn=""
        gaster=""
        iBoot32Patcher=""
        xpwntool=""
        hfsplus=""
        pzb=""
        jq=""
        ticket=""
        validate=""
        img4tool=""
        irecovery2=""
        aria2c=""
        tsschecker=""
        z7z=""
        sha1sum="$(command -v shasum) -a 1"
        bspatch="$(command -v bspatch)"
    elif [[ "$platform" == "linux" ]]; then
        export LD_LIBRARY_PATH="$dir/lib"
        sshpass="sudo "
        irecovery="sudo "
        iproxy="sudo "
        ipwnder="sudo "
        idevicerestore="sudo LD_LIBRARY_PATH=$dir/lib "
        futurerestore="sudo "
        futurerestore_old="sudo "
        ideviceinfo="sudo LD_LIBRARY_PATH=$dir/lib "
        dmg="sudo "
        zenity="sudo GSETTINGS_BACKEND=memory $(command -v zenity)"
        ideviceactivation="sudo LD_LIBRARY_PATH=$dir/lib "
        ideviceinstaller="sudo LD_LIBRARY_PATH=$dir/lib "
        primepwn="sudo "
        gaster="sudo "
        iBoot32Patcher="sudo "
        xpwntool="sudo "
        hfsplus="sudo "
        pzb="sudo "
        jq="sudo "
        ticket="sudo "
        validate="sudo "
        img4tool="sudo "
        irecovery2="sudo "
        aria2c="sudo "
        z7z="sudo "
        tsschecker="sudo "
        afc=”sudo“
        bspatch=$dir/bspatch
    fi
    sshpass+=$dir/sshpass
    irecovery+="$dir/irecovery"
    iproxy+=$dir/iproxy
    ipwnder+=$dir/ipwnder
    idevicerestore+=$dir/idevicerestore
    futurerestore+=$dir/futurerestore
    futurerestore_old+=$dir/futurerestore_old
    ideviceinfo+=$dir/ideviceinfo
    dmg+=$dir/dmg
    ideviceactivation+=$dir/ideviceactivation
    ideviceinstaller+=$dir/ideviceinstaller
    primepwn+=$dir/primepwn
    iBoot32Patcher+=$dir/iBoot32Patcher
    xpwntool+=$dir/xpwntool
    hfsplus+=$dir/hfsplus
    pzb+=$dir/pzb
    jq+=$dir/jq
    ticket+=$dir/ticket
    validate+=$dir/validate
    img4tool+=$dir/img4tool
    irecovery2+=$dir/irecovery2
    aria2c+=$dir/aria2c
    tsschecker+=$dir/tsschecker
    z7z+=$dir/7zz
    sha1sum="$(command -v shasum) -a 1"
}

set_ssh_config() {
    if [ -z "$1" ]; then
        cp ../resources/ssh_config .
        if [[ $(ssh -V 2>&1 | grep -c SSH_8.8) == 1 || $(ssh -V 2>&1 | grep -c SSH_8.9) == 1 ||
            $(ssh -V 2>&1 | grep -c SSH_9.) == 1 || $(ssh -V 2>&1 | grep -c SSH_1) == 1 ]]; then
            echo "    PubkeyAcceptedAlgorithms +ssh-rsa" >> ./ssh_config
        elif [[ $(ssh -V 2>&1 | grep -c SSH_6) == 1 ]]; then
            cat $script_dir/bin/Others/ssh_config | sed "s,Add,#Add,g" | sed "s,HostKeyA,#HostKeyA,g" > ssh_config
        fi
    fi
    
    if [ -z "$1" ]; then
        ssh="$dir/sshpass -p alpine ssh -F ./ssh_config"
        scp="$dir/sshpass -p alpine scp -F ./ssh_config"
    fi
    
    if [[ "$1" == "pass" ]]; then
        ssh="$dir/sshpass -p $2 ssh -F ./ssh_config"
        scp="$dir/sshpass -p $2 scp -F ./ssh_config"
    fi
}

ssh_check() {
    local message
    if [[ "$1" == "$ssh_port" ]]; then
        local port=$ssh_port
    elif [[ "$ship_ssh_check" == 1 ]]; then
        return
    else
        local port=$openssh_port
    fi
    message=$($ssh -p $ssh_port root@127.0.0.1 "echo sshtest")
    if [[ "$message" == "sshtest" ]]; then
        if [[ "$2" != "q" ]]; then
            log SSH connection successful✅
        fi
        sshyes=1
    else
        if [[ "$2" != "q" ]]; then
            log "SSH connection failed ❎ (You can try adding --ship-ssh-check and --menu to the end of the script to access the SSH menu)"
        fi
        sshyes=no
        go_to_menu
    fi
}

checkmode() {
    if [ "$1" = "DFU" ]; then
        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
            if [[ "$2" != "none" ]]; then
                log "[*] Waiting for the device to enter DFU mode"
            fi
        fi
        while ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); do
            sleep 1
        done
    elif [ "$1" = "rec" ]; then
        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (Recovery Mode)' >> /dev/null); then
            if [[ "$2" != "none" ]]; then
                log "[*] Waiting for the device to enter Recovery mode"
            fi
        fi
        while ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (Recovery Mode)' >> /dev/null); do
            sleep 1
        done
    elif [ "$1" = "nor" ]; then
        if ! (system_profiler SPUSBDataType 2> /dev/null | grep -E ' (iPod|iPhone|iPad)' >> /dev/null); then
            if [[ "$2" != "none" ]]; then
                log "[*] Waiting for the device to enter Normal mode"
            fi
        fi
        while ! (system_profiler SPUSBDataType 2> /dev/null | grep -E ' (iPod|iPhone|iPad)' >> /dev/null); do
            sleep 1
        done
    elif [ "$1" = "DFUreal" ]; then
        if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' USB DFU Device' >> /dev/null); then
            if [[ "$2" != "none" ]]; then
                log "[*] Waiting for the device to enter DFU mode"
            fi
        fi
        while ! (system_profiler SPUSBDataType 2> /dev/null | grep ' USB DFU Device' >> /dev/null); do
            sleep 1
        done
    elif [ "$1" = "DFUall" ]; then
        while true;do
            if (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
                break
            fi
            sleep 1
            if (system_profiler SPUSBDataType 2> /dev/null | grep ' USB DFU Device' >> /dev/null); then
                break
            fi
        done
    fi
}

device_info() {
    if [[ -z $device_type ]]; then
        device_type=$($irecovery -q | grep -i "product" | awk -F': ' '{print $2}')
    else
        if [[ $device_type =~ ^(iPhone|iPad|iPod)[1-9][0-9]*,[0-9]+$ ]]; then
            :
        else
            while true; do
                error Device type entered incorrectly,please please re-enter.
                read $device_type
                if [[ $device_type =~ ^(iPhone|iPad|iPod)[1-9][0-9]*,[0-9]+$ ]]; then
                    break
                fi
            done
        fi
    fi
    if [ ! -d "$saved/$device_type" ]; then
        mkdir $saved/$device_type
    fi
    case $device_type in
        iPhone1,* | iPod1,1 )
            device_proc=1;; # S5L8900
        iPad1,1 | iPhone[23],* | iPod[234],1 )
            device_proc=4;; # A4/S5L8720/8920/8922
        iPad2,* | iPad3,[123] | iPhone4,1 | iPod5,1 )
            device_proc=5;; # A5
        iPad3,* | iPhone5,* )
            device_proc=6;; # A6            
    esac
            case $device_type in
            iPad1,1  ) device_model="k48";;
            iPad2,1  ) device_model="k93";;
            iPad2,2  ) device_model="k94";;
            iPad2,3  ) device_model="k95";;
            iPad2,4  ) device_model="k93a";;
            iPad2,5  ) device_model="p105";;
            iPad2,6  ) device_model="p106";;
            iPad2,7  ) device_model="p107";;
            iPad3,1  ) device_model="j1";;
            iPad3,2  ) device_model="j2";;
            iPad3,3  ) device_model="j2a";;
            iPad3,4  ) device_model="p101";;
            iPad3,5  ) device_model="p102";;
            iPad3,6  ) device_model="p103";;
            iPhone1,1) device_model="m68";;
            iPhone1,2) device_model="n82";;
            iPhone2,1) device_model="n88";;
            iPhone3,1) device_model="n90";;
            iPhone3,2) device_model="n90b";;
            iPhone3,3) device_model="n92";;
            iPhone4,1) device_model="n94";;
            iPhone5,1) device_model="n41";;
            iPhone5,2) device_model="n42";;
            iPhone5,3) device_model="n48";;
            iPhone5,4) device_model="n49";;
            iPod1,1 ) device_model="n45";;
            iPod2,1 ) device_model="n72";;
            iPod3,1 ) device_model="n18";;
            iPod4,1 ) device_model="n81";;
            iPod5,1 ) device_model="n78";;
        esac
    
}

######pwn######
device_pwn() {
    local a5
    log Getting device info and pwning... this may take a second
    if [[ -z $device_pwnd ]]; then
        case $device_proc in
            1 ) device_s5l8900xall ;;
            4 ) 
            case $device_type in
                iPad1,1 | iPhone3,* | iPod[24],1 )
                log Pwn:primepwn
                $primepwn
                ;;
                * )
                log Pwn:ipwnder
                $ipwnder
                ;;
            esac
             ;;
            5 ) a5=1 ;;
            6 ) $ipwnder ;;
        esac
    fi
    if [[ $device_proc == 5 ]]; then
        if [[ $ship_send_pwnibss != 1 ]]; then 
            while true; do
                local device_pwnd2="$($irecovery -q | grep "PWND" | cut -c 7-)"
                if [ "$device_pwnd2" != "checkm8" ]; then
                    print "pwn a5 device needs Arduino+USB Host Shield or Pi Pico"
                    pause when you have been pwned,press enter to continue
                else
                    break
                fi
            done
            device_send_unpacked_ibss
        else
            warning make sure you have been sent pwnibss
            pause press enter to continue
        fi
    fi
     device_pwnd1="$($irecovery -q | grep "PWND" | cut -c 7-)"
    if [[ $device_proc != 1 ]]; then
        if [[ $device_proc != 5 ]]; then
            if [[ -n $device_pwnd1 ]]; then
                log Device has been pwned✅
            else
                error "Unable to pwn device❎(close i4/3u tools and try again)"
                exit 1
            fi
        fi
    fi
}

device_send_unpacked_ibss() {
    local pwnrec="pwned iBSS"
    device_rd_build=
    patch_ibss
    log "Sending unpacked iBSS..."
    $primepwn pwnediBSS
    local tool_pwned=$?
    if [[ $tool_pwned != 0 ]]; then
        error "Failed to send iBSS. Your device has likely failed to enter PWNED DFU mode." \
        "* You might need to exit DFU and (re-)enter PWNED DFU mode before retrying."
    fi
    sleep 1
    log "Checking for device"
    local irec="$($irecovery -q 2>&1)"
    device_pwnd="$(echo "$irec" | grep "PWND" | cut -c 7-)"
    if [[ -z $device_pwnd && $irec != "ERROR"* ]]; then
        log "Device should now be in $pwnrec mode."
        log Device has been pwned✅
    else
        error "Device failed to enter $pwnrec mode."
        error "Unable to pwn device❎(close i4/3u tools and try again)"
        exit 1
    fi
}



#####main######
ramdisk() {
    local comps=("iBSS" "iBEC" "DeviceTree" "Kernelcache")
    local name
    local iv
    local key
    local path
    local url
    local decrypt
    local ramdisk_path
    local version
    local build_id
    local mode="$1"
    local rec=2
    all_flash="Firmware/all_flash/all_flash.${device_model}ap.production"
    if [[ $1 == "setnvram" ]]; then
        rec=$2
    fi
    if [[ $1 != "justboot" ]]; then
        comps+=("RestoreRamdisk")
    fi
    case $device_type in
        iPhone1,[12] | iPod1,1 ) device_target_build="7E18"; device_target_vers="3.1.3";;
        iPod2,1 ) device_target_build="8C148";;
        iPod3,1 | iPad1,1 ) device_target_build="9B206";;
        iPhone2,1 | iPod4,1 ) device_target_build="10B500";;
        iPhone5,[34] ) device_target_build="11D257";;
        * ) device_target_build="10B329";;
    esac
    if [[ -n $device_rd_build_custom ]]; then
        if [[ $ship_build_check != 1 ]]; then
            if [[ "$device_rd_build_custom" =~ ^[0-9]+[A-Za-z][0-9]+[a-z]?$ ]]; then
                log Get version info
                get_firmware_info build $device_rd_build_custom
                if [ -z "$url" ]; then
                    error Unable get url of this version
                    exit 1
                fi
                device_rd_build=$device_rd_build_custom
            else
                log Get version info
                get_firmware_info ver $device_rd_build_custom
                if [ -z "$url" ]; then
                    error Unable get url of this version
                    pause
                    exit 1
                fi
                device_rd_build=$buildid
            fi
        else
            device_rd_build=$device_rd_build_custom
        fi
        tip "use custom version:$device_rd_build"
    fi
    if [[ -n $device_rd_build ]]; then
        device_target_build=$device_rd_build
        device_rd_build=
    fi
    version=$device_target_vers
    build_id=$device_target_build
    device_fw_key_check
    ipsw_get_url $build_id $version
    ramdisk_path="../saved/$device_type/ramdisk_$build_id"
    mkdir $ramdisk_path 2>/dev/null
    for getcomp in "${comps[@]}"; do
        name=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .filename')
        iv=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .iv')
        key=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .key')
        case $getcomp in
            "iBSS" | "iBEC" ) path="Firmware/dfu/";;
            "DeviceTree" )
                path="Firmware/all_flash/"
                case $build_id in
                    14[EFG]* ) :;;
                    * ) path="$all_flash/";;
                esac
            ;;
            * ) path="";;
        esac
        if [[ -z $name ]]; then
            local hwmodel="$device_model"
            case $build_id in
                14[EFG]* )
                    case $device_type in
                        iPhone5,[12] ) hwmodel="iphone5";;
                        iPhone5,[34] ) hwmodel="iphone5b";;
                        iPad3,[456] )  hwmodel="ipad3b";;
                    esac
                ;;
                [789]* | 10* | 11* ) hwmodel+="ap";;
            esac
            case $getcomp in
                "iBSS" | "iBEC" ) name="$getcomp.$hwmodel.RELEASE.dfu";;
                "DeviceTree" )    name="$getcomp.${device_model}ap.img3";;
                "Kernelcache" )   name="kernelcache.release.$hwmodel";;
            esac
        fi

        log "$getcomp"
        if [[ -n $ipsw_justboot_path ]]; then
            file_extract_from_archive "$ipsw_justboot_path.ipsw" "${path}$name"
        elif [[ -s $ramdisk_path/$name ]]; then
            cp $ramdisk_path/$name .
        else
            "$dir/pzb" -g "${path}$name" -o "$name" "$ipsw_url"
        fi
        if [[ ! -s $name ]]; then
            error "Failed to get $name. Please run the script again."
        fi
        if [[ ! -s $ramdisk_path/$name ]]; then
            cp $name $ramdisk_path/
        fi
        mv $name $getcomp.orig
        if [[ $getcomp == "Kernelcache" || $getcomp == "iBSS" ]] && [[ $device_proc == 1 || $device_type == "iPod2,1" ]]; then
            decrypt="-iv $iv -k $key"
            "$dir/xpwntool" $getcomp.orig $getcomp.dec $decrypt
        elif [[ $build_id == "14"* ]]; then
            cp $getcomp.orig $getcomp.dec
        else
            "$dir/xpwntool" $getcomp.orig $getcomp.dec -iv $iv -k $key -decrypt
        fi
    done

    if [[ $1 != "justboot" ]]; then
        log "Make RestoreRamdisk"
        "$dir/xpwntool" RestoreRamdisk.dec Ramdisk.raw
        if [[ $device_proc != 1 ]]; then
            "$dir/hfsplus" Ramdisk.raw grow 30000000
            "$dir/hfsplus" Ramdisk.raw untar ../resources/sbplist.tar
        fi
    fi

    if [[ $device_proc == 1 ]]; then
        $bspatch Ramdisk.raw Ramdisk.patched ../resources/patch/018-6494-014.patch
        "$dir/xpwntool" Ramdisk.patched Ramdisk.dmg -t RestoreRamdisk.dec
        log "Make iBSS"
        $bspatch iBSS.orig iBSS ../resources/patch/iBSS.${device_model}ap.RELEASE.patch
        log "Make Kernelcache"
        mv Kernelcache.dec Kernelcache0.dec
        $bspatch Kernelcache0.dec Kernelcache.patched ../resources/patch/kernelcache.release.s5l8900x.patch
        "$dir/xpwntool" Kernelcache.patched Kernelcache.dec -t Kernelcache.orig $decrypt
        rm DeviceTree.dec
        mv DeviceTree.orig DeviceTree.dec
    elif [[ $device_type == "iPod2,1" ]]; then
        "$dir/hfsplus" Ramdisk.raw untar ../resources/ssh_old.tar
        "$dir/xpwntool" Ramdisk.raw Ramdisk.dmg -t RestoreRamdisk.dec
        log "Make iBSS"
        $bspatch iBSS.dec iBSS.patched ../resources/patch/iBSS.${device_model}ap.RELEASE.patch
        "$dir/xpwntool" iBSS.patched iBSS -t iBSS.orig
        log "Make Kernelcache"
        mv Kernelcache.dec Kernelcache0.dec
        $bspatch Kernelcache0.dec Kernelcache.patched ../resources/patch/kernelcache.release.${device_model}.patch
        "$dir/xpwntool" Kernelcache.patched Kernelcache.dec -t Kernelcache.orig $decrypt
        rm DeviceTree.dec
        mv DeviceTree.orig DeviceTree.dec
    else
        if [[ $1 != "justboot" ]]; then
            "$dir/hfsplus" Ramdisk.raw untar ../resources/ssh.tar
            if [[ $1 == "jailbreak" && $device_vers == "8"* ]]; then
                "$dir/hfsplus" Ramdisk.raw untar ../resources/jailbreak/daibutsu/bin.tar
            fi
            "$dir/hfsplus" Ramdisk.raw mv sbin/reboot sbin/reboot_bak
            "$dir/hfsplus" Ramdisk.raw mv sbin/halt sbin/halt_bak
            case $build_id in
                 "12"* | "13"* | "14"* )
                    echo '#!/bin/bash' > restored_external
                    echo "/sbin/sshd; exec /usr/local/bin/restored_external_o" >> restored_external
                    "$dir/hfsplus" Ramdisk.raw mv usr/local/bin/restored_external usr/local/bin/restored_external_o
                    "$dir/hfsplus" Ramdisk.raw add restored_external usr/local/bin/restored_external
                    "$dir/hfsplus" Ramdisk.raw chmod 755 usr/local/bin/restored_external
                    "$dir/hfsplus" Ramdisk.raw chown 0:0 usr/local/bin/restored_external
                ;;
            esac
            "$dir/xpwntool" Ramdisk.raw Ramdisk.dmg -t RestoreRamdisk.dec
        fi
        log "Make iBSS"
        "$dir/xpwntool" iBSS.dec iBSS.raw
        if [[ $device_type == "iPad2,"* || $device_type == "iPhone3,3" ]]; then
            case $build_id in
                8[FGHJKL]* | 8E600 | 8E501 ) device_boot4=1;;
            esac
        fi
        if [[ $device_boot4 == 1 ]]; then
            "$dir/iBoot32Patcher" iBSS.raw iBSS.patched --rsa --debug -b "-v amfi=0xff cs_enforcement_disable=1"
        else
            "$dir/iBoot32Patcher" iBSS.raw iBSS.patched --rsa --debug -b "$device_bootargs"
        fi
        "$dir/xpwntool" iBSS.patched iBSS -t iBSS.dec
        if [[ $build_id == "7"* || $build_id == "8"* ]] && [[ $device_type != "iPad"* ]]; then
            :
        else
            log "Make iBEC"
            "$dir/xpwntool" iBEC.dec iBEC.raw
            if [[ $1 == "justboot" ]]; then
                "$dir/iBoot32Patcher" iBEC.raw iBEC.patched --rsa --debug -b "$device_bootargs"
            else
                "$dir/iBoot32Patcher" iBEC.raw iBEC.patched --rsa --debug -b "rd=md0 -v amfi=0xff amfi_get_out_of_my_way=1 cs_enforcement_disable=1 pio-error=0"
            fi
            "$dir/xpwntool" iBEC.patched iBEC -t iBEC.dec
        fi
    fi

    if [[ $device_boot4 == 1 ]]; then
        log "Make Kernelcache"
        mv Kernelcache.dec Kernelcache0.dec
        "$dir/xpwntool" Kernelcache0.dec Kernelcache.raw
        $bspatch Kernelcache.raw Kernelcache.patched ../resources/patch/kernelcache.release.${device_model}.${build_id}.patch
        "$dir/xpwntool" Kernelcache.patched Kernelcache.dec -t Kernelcache0.dec
    fi

    mv iBSS iBEC DeviceTree.dec Kernelcache.dec Ramdisk.dmg $ramdisk_path 2>/dev/null

    if [[ $device_argmode == "none" ]]; then
        log "Done creating SSH ramdisk files: saved/$device_type/ramdisk_$build_id"
            if [[ $arg_l == 1 ]]; then
                log "Use ./sshrd32 boot to boot device"
            fi
        return
    fi
    if [[ $ship_boot != 1 ]]; then
        device_pwn
        if [[ $device_type == "iPad1,1" && $build_id != "9"* ]]; then
            patch_ibss
            log "Sending iBSS..."
            $irecovery -f pwnediBSS.dfu
            sleep 2
            log "Sending iBEC..."
            $irecovery -f $ramdisk_path/iBEC
        elif (( device_proc < 5 )) && [[ $device_pwnrec != 1 ]]; then
            log "Sending iBSS..."
            $irecovery -f $ramdisk_path/iBSS
        fi
        sleep 2
        #if [[ $build_id != "7"* && $build_id != "8"* ]]; then #someting wrong here
        if [[ $device_proc != 1 ]]; then
            log "Sending iBEC..."
            $irecovery -f $ramdisk_path/iBEC
            if [[ $device_pwnrec == 1 ]]; then
                $irecovery -c "go"
            fi
        fi
        sleep 3
        checkmode rec
        if [[ $1 != "justboot" ]]; then
            log "Sending ramdisk..."
            $irecovery -f $ramdisk_path/Ramdisk.dmg
            log "Running ramdisk"
            $irecovery -c "getenv ramdisk-delay"
            $irecovery -c ramdisk
            sleep 2
        fi
        log "Sending DeviceTree..."
        $irecovery -f $ramdisk_path/DeviceTree.dec
        log "Running devicetree"
        $irecovery -c devicetree
        log "Sending KernelCache..."
        $irecovery -f $ramdisk_path/Kernelcache.dec
        $irecovery -c bootx

        if [[ $1 == "justboot" ]]; then
            log "Device should now boot."
            return
        fi
        log "Booting, please wait..."
        sleep 6
    fi
    if [[ $just_boot == 1 ]]; then
        log "Done,use ./sshrd32.sh ssh or ./sshrd32.sh --menu to connect device"
        return
    else
        if [[ -n $1 ]]; then
            device_iproxy
        else
            device_iproxy no-logging
        fi
        local found
        log "Waiting for device..."
        tip "* You may need to unplug and replug your device."
        local try=0
        while [[ $found != 1 ]]; do
            found=$($ssh -p $ssh_port root@127.0.0.1 "echo 1" 2>/dev/null)
            try=$((try + 1))
            if [[ $try == 10 ]]; then
                error "Unable to connect SSH, please try boot again"
                return 1
            fi
            sleep 2
        done
        if [[ $device_proc == 1 || $device_type == "iPod2,1" ]]; then
            log "Transferring some files"
            tar -xvf ../resources/ssh.tar ./bin/chmod ./bin/chown ./bin/cp ./bin/dd ./bin/mount.sh ./bin/tar ./usr/bin/date ./usr/bin/df ./usr/bin/du
            $ssh -p $ssh_port root@127.0.0.1 "rm -f /bin/mount.sh /usr/bin/date"
            $scp -P $ssh_port bin/* root@127.0.0.1:/bin
            $scp -P $ssh_port usr/bin/* root@127.0.0.1:/usr/bin
        fi
        
        if [[ $no_menu != "1" ]]; then
            ssh_menu
        fi
        if [[ $just_jailbreak == 1 ]]; then
            jailbreak_sshrd
        elif [[ $just_get_ios_ver == 1 ]]; then
            check_iosvers
        elif [[ $just_hacktivate == 1 ]]; then
            device_hacktivate
        elif [[ $just_part2 == 1 ]]; then
            device_hacktivate_part2
        fi
    fi
}


main() {
    if [[ $debug_mode == 1 ]]; then
        debug_func
    fi
    if [[ "$just_make" != "1" ]] && [[ -z "$device_type" ]]; then
        if [[ "$ship_boot" != "1" ]]; then
            log "[*] Waiting for the device to enter DFU mode"
            checkmode DFUall
        fi
    fi
    device_info
    ramdisk
}

ssh_menu() {
    local exit
    if [[ "$ship_boot" == "1" ]]; then
        device_iproxy
        ship_boot=
    fi
    if [[ $debug_mode == 1 ]]; then
        pause
    fi
    clear
    tip  "*** SSHRD_Script_32Bit ***"
    tip  "- $platform_message -"
    tip  "- Script by MrY0000 -"
    tip  "- Forked from Legacy-iOS-Kit(https://github.com/LukeZGD/Legacy-iOS-Kit) -"
    input "Select option:"
    local options=()
    local selected
    options+=("SSH Connection")
    options+=("Jailbreak")
    #options+=("Activate Device")
    #options+=("Pseudo Activation TEST")
    #options+=("Backup Activation Files")
    #options+=("Restore Activation Files")
    options+=("Check iOS Version")
    #options+=("Enable Battery Percentage")
    options+=("Clear NVRAM")
    options+=("Reboot")
    options+=("Exit")
    #options+=("Return to Home")
    select_option "${options[@]}"
    selected="${options[$?]}"
        case $selected in
            "SSH Connection")
                ssh_message
                $ssh -p $ssh_port root@127.0.0.1
                ;;
            "Activate Device")
                activition; pause;;
            "Pseudo Activation TEST")
                hacktivate_device; go_to_menu ;;
            "Jailbreak")
                jailbreak_sshrd; pause;;
            "Backup Activation Files")
                activition_backup; pause;;
            "Check iOS Version")
                check_iosvers; pause;;
            "Enable Battery Percentage")
                device_add_battery_percentage; pause;;
            "Clear NVRAM")
                $ssh -p $ssh_port root@127.0.0.1 "nvram -c" ;;
            "Reboot")
                $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"; exit=1;;
            "Exit" )
                exit=1
                ;;
        esac
    if [[ "$exit" != "1" ]]; then
        ssh_menu
    fi
}

ssh_message() {
    print "* For accessing data, note the following:"
    print "* Host: sftp://127.0.0.1 | User: root | Password: alpine | Port: $ssh_port"
    echo
    print "* Other Useful SSH Ramdisk commands:"
    print "* Clear NVRAM with this command:"
    print "    nvram -c"
    print "* Erase All Content and Settings with this command (iOS 9+ only):"
    print "    nvram oblit-inprogress=5"
    print "* To reboot, use this command:"
    print "    reboot_bak"
    print "* Remove Setup.app:"
    print "    rm -rf /mnt1/Applications/Setup.app"
    echo

}

###functions###

check_iosvers() {
    local options
    local selected
    device_datetime_cmd nopause
    local mount_command="mount.sh root"
    device_vers=
    device_build=
    log "Mounting root filesystem"
    $ssh -p $ssh_port root@127.0.0.1 "$mount_command"
    sleep 1
    log "Getting iOS version"
    $scp -P $ssh_port root@127.0.0.1:/mnt1/System/Library/CoreServices/SystemVersion.plist .
    rm -f BuildVer Version
    if [[ $platform == "macos" ]]; then
        plutil -extract 'ProductVersion' xml1 SystemVersion.plist -o Version
        device_vers=$(cat Version | sed -ne '/<string>/,/<\/string>/p' | sed -e "s/<string>//" | sed "s/<\/string>//" | sed '2d')
        plutil -extract 'ProductBuildVersion' xml1 SystemVersion.plist -o BuildVer
        device_build=$(cat BuildVer | sed -ne '/<string>/,/<\/string>/p' | sed -e "s/<string>//" | sed "s/<\/string>//" | sed '2d')
    else
        device_vers=$(cat SystemVersion.plist | grep -i ProductVersion -A 1 | grep -oPm1 "(?<=<string>)[^<]+")
        device_build=$(cat SystemVersion.plist | grep -i ProductBuildVersion -A 1 | grep -oPm1 "(?<=<string>)[^<]+")
    fi
    if [[ -n $device_vers ]]; then
        log "Get iOS Version successfully"
        tip "* iOS Version: $device_vers ($device_build)"
        if [[ $1 != nopause ]]; then
            pause
            return
        fi
    else
        error "Unable get iOS Version"
        if [[ $1 != nopause ]]; then
            pause
            return
        fi
    fi
}

device_datetime_cmd() {
    log "Running command to Update DateTime"
    $ssh -p $ssh_port root@127.0.0.1 "date -s @$(date +%s)"
    if [[ $1 != "nopause" ]]; then
        log "Done"
        pause
    fi
}

jailbreak_sshrd() {
    local vers
    local build
    local untether
    jelbrek=../resources/Jailbreak
    device_jailbreak=1
    check_iosvers nopause
    vers=$device_vers
    build=$device_build

    if [[ -z $device_vers ]]; then
        error Unable get iOS version,please try again
        pause
        return
    fi

    if [[ -n $($ssh -p $ssh_port root@127.0.0.1 "ls /mnt1/bin/bash 2>/dev/null") ]]; then
        warning "Your device seems to be already jailbroken. Cannot continue."
        if [[ $just_jailbreak == 1 ]]; then
            $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
        else
            pause
            return
        fi
    fi

    case $vers in
        9.3.[4231] | 9.3 ) untether="untetherhomedepot.tar";;
        9.2* | 9.1 )       untether="untetherhomedepot921.tar";;
        9.0* )             untether="everuntether.tar";;
        8* )               untether="daibutsu/untether.tar";;
        7.1* )
            case $device_type in
                iPod* ) untether="panguaxe-ipod.tar";;
                *     ) untether="panguaxe.tar";;
            esac
        ;;
        7.0* ) # remove for lyncis 7.0.x
            untether="evasi0n7-untether.tar"
            if [[ $device_type == "iPhone5,3" || $device_type == "iPhone5,4" ]] && [[ $vers == "7.0" ]]; then
                untether="evasi0n7-untether-70.tar"
            fi
            ;;
        6.1.[6543] )       untether="p0sixspwn.tar";;
        6* )               untether="evasi0n6-untether.tar";;
        5* )               untether="g1lbertJB/${device_type}_${build}.tar";;
        4.2.[8761] | 4.[10]* | 3.2* | 3.1.3 )
            untether="greenpois0n/${device_type}_${build}.tar"
        ;;
        4.[32]* )
            case $device_type in
                # untether=1 means no untether package, but the var still needs to be set
                iPad2,* | iPhone3,3 ) untether=1;;
                * ) untether="g1lbertJB/${device_type}_${build}.tar";;
            esac
        ;;
        3* ) [[ $device_type == "iPhone2,1" ]] && untether=1;;
        '' )
            warning "Something wrong happened. Failed to get iOS version."
            if [[ $just_jailbreak == 1 ]]; then
                $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
            else
                pause
                return
            fi
        ;;
    esac

    if [[ -z $untether ]]; then
        warning "iOS $vers is not supported for jailbreaking with SSHRD."
        if [[ $just_jailbreak == 1 ]]; then
            $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
        else
            pause
            return
        fi
    fi
    log "Nice, iOS $vers is compatible."
    log "Mounting data partition"
    $ssh -p $ssh_port root@127.0.0.1 "mount.sh pv"

    # do stuff
    case $vers in
        6* )    device_send_rdtar fstab_rw.tar;;
        4.2.[8761] )
            log "launchd to punchd"
            $ssh -p $ssh_port root@127.0.0.1 "[[ ! -e /mnt1/sbin/punchd ]] && mv /mnt1/sbin/launchd /mnt1/sbin/punchd"
        ;;
    esac
    case $vers in
        5* ) device_send_rdtar g1lbertJB.tar;;
        [43]* )
            log "fstab"
            local fstab="fstab_new" # disk0s2s1 data
            if [[ $device_proc == 1 || $device_type == "iPod2,1" ]]; then
                fstab="fstab_old" # disk0s2 data
            fi
            $scp -P $ssh_port $jelbrek/$fstab root@127.0.0.1:/mnt1/private/etc/fstab
            $ssh -p $ssh_port root@127.0.0.1 "rm /mnt1/private/var/mobile/Library/Caches/com.apple.mobile.installation.plist" # idk if this is really needed but ill keep it
        ;;
    esac

    log "Sending $untether"
    $scp -P $ssh_port $jelbrek/$untether root@127.0.0.1:/mnt1
    case $vers in
        [543]* ) untether="${device_type}_${build}.tar";; # remove folder name after sending tar
    esac
    # 3.1.3–4.1 untether must be extracted before data partition mount
    case $vers in
        4.[10]* | 3.2* | 3.1.3 )
            log "Extracting $untether"
            $ssh -p $ssh_port root@127.0.0.1 "tar -xvf /mnt1/$untether -C /mnt1; rm /mnt1/$untether"
        ;;
    esac
    # untether extraction
    case $vers in
        4.[10]* | 3* ) :;; # already extracted
        * )
            if [[ $untether != 1 ]]; then
                log "Extracting $untether"
                $ssh -p $ssh_port root@127.0.0.1 "tar -xvf /mnt1/$untether -C /mnt1; rm /mnt1/$untether"
            fi
        ;;
    esac
    device_send_rdtar freeze.tar data
    if [[ $vers == "9"* ]]; then
        # required stuff for everuntether and untetherhomedepot
        [[ $vers != "9.0"* ]] && device_send_rdtar daemonloader.tar
        device_send_rdtar launchctl.tar
    fi
    if [[ $ipsw_openssh == 1 ]]; then
        device_send_rdtar sshdeb.tar
    fi
    case $vers in
        [543]* ) device_send_rdtar cydiasubstrate.tar;;
    esac
    case $vers in
        3* ) device_send_rdtar cydiahttpatch.tar;;
    esac
    if [[ $1 != noreboot ]]; then
        log "Rebooting"
        $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
    fi

    log "Jailbreak successfully✅"
    exit=1
}

device_hacktivate() {
    local ver
    local build
    local 
    log Get ios version
    check_iosvers
    cut_os_vers $device_vers
    case $major_ver in
        [56]* )
            if [[ -n $($ssh -p $ssh_port root@127.0.0.1 "ls /mnt1/bin/bash 2>/dev/null") ]]; then
                log Great,this device has been jailbroken,continue
            else
                yesno "Since jailbreaking is required for hacktivate-activation in iOS 5-6, do you want jailbreak? (y > jailbreak) (n > go to ssh menu)"
                if [[ $? == 1 ]]; then
                    jailbreak_sshrd noreboot
                    if [[ -n $($ssh -p $ssh_port root@127.0.0.1 "ls /mnt1/bin/bash 2>/dev/null") ]]; then
                        log Great,this device has been jailbroken,continue
                    else
                        error "This device also hasn't jailbroken,press enter to go to ssh menu"
                        ssh_menu
                        return
                    fi
                else
                    ssh_menu
                    return
                fi
            fi
            log Mount Filesystem
            $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
            log Rename orgin file
            $ssh -p $ssh_port root@127.0.0.1 "mv /mnt1/usr/libexec/lockdownd /mnt1/usr/libexec/lockdownd.bak"
            log upload new file
            $scp -P $ssh_port $script_dir/bin/Others/lockdownd root@127.0.0.1:/mnt1/usr/libexec
            log Set permissions
            $ssh -p $ssh_port root@127.0.0.1 "chmod 755 /mnt1/usr/libexec/lockdownd"
            log Rebooting
            $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
            go_to_menu
            ;;
        [789]* )
            log Mount Filesystem
            $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
            log Download files
            $ssh -p $ssh_port root@127.0.0.1 "mv /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist /mnt2/mobile/Media"
            local message=$($ssh -p $ssh_port root@127.0.0.1 "ls /mnt2/mobile/Media/com.apple.MobileGestalt.plist")
            if [[ $message != "/mnt2/mobile/Media/com.apple.MobileGestalt.plist" ]]; then
                error Download failed
                pause Press enter to go to ssh menu
                ssh_menu
                return
            else
                #part1
                log Rebooting
                pause
                $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
                sleep 5
                checkmode normal
                log 请信任设备后按回车
                pause
                $afc download /com.apple.MobileGestalt.plist $tmp
                if [[ ! -f "$tmp/com.apple.MobileGestalt.plist" ]]; then
                    error Download failed
                    pause Press enter to exit
                    return
                else
                    log "Patch files"
                    $activition $tmp/com.apple.MobileGestalt.plist
                    log Upload files
                    $afc upload $tmp/com.apple.MobileGestalt.plist /
                fi
            fi
            log "Done,part1 has been completed,use ./sshrd32.sh --hac-part-2 to start part 2"
            ;;
        * )
            warning This iOS version is unsupport
            pause Press enter to enter ssh menu
            ;;
    esac
}

device_hacktivate_part2() {
    ##part2
    log Mount Filesystem
    $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
    log Rename Setup.app
    $ssh -p $ssh_port root@127.0.0.1 "mv /mnt1/Applications/Setup.app /mnt1/Applications/Setup.app.bak"
    log Replace original files
    $ssh -p $ssh_port root@127.0.0.1 "mv /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist.bak"
    $ssh -p $ssh_port root@127.0.0.1 "mv /mnt2/mobile/Media/com.apple.MobileGestalt.plist /mnt2/mobile/Library/Caches"
    log Rebooting
    $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
}


###tools###

cut_os_vers() {
    if [[ $1 != device ]]; then
        device_det=$(echo "$1" | cut -c 1)
        device_det2=$(echo "$1" | cut -c -2)
        device_det3=$(echo "$1" | cut -c 3)
        device_det4=$(echo "$1" | cut -c 4)
        device_det5=$(echo "$1" | cut -c 4-5)
        device_det6=$(echo "$1" | cut -c 5-6)
    else
        device_det=$(echo "$2" | cut -c 1)
        device_det2=$(echo "$2" | cut -c -2)
        device_det3=$(echo "$2" | cut -c 3)
        device_det4=$(echo "$2" | cut -c 4)
        device_det5=$(echo "$2" | cut -c 4-5)
        device_det6=$(echo "$2" | cut -c 5-6)
    fi
    if [[ $1 != device ]]; then
        if [[ $device_det == 1 ]]; then
            major_ver=$device_det2
            minor_ver=$device_det4
            nano_ver=$device_det6
            nano_ver_wtd=$(echo "$nano_ver" | cut -c 2)
        else
            major_ver=$device_det
            minor_ver=$device_det3
            nano_ver=$device_det5
            nano_ver_wtd=$(echo "$nano_ver" | cut -c 2)
        fi
    else
        if [[ $device_det == 1 ]]; then
            device_major_ver=$device_det2
            device_minor_ver=$device_det4
            device_nano_ver=$device_det6
            device_nano_ver_wtd=$(echo "$device_nano_ver" | cut -c 2)
        else
            device_major_ver=$device_det
            device_minor_ver=$device_det3
            device_nano_ver=$device_det5
            device_nano_ver_wtd=$(echo "$device_nano_ver" | cut -c 2)
        fi
    fi
}

get_firmware_info() {
    local version=
    local build=
    buildid=
    filesize=
    sha1=
    sha256=
    md5=
    signed=
    releasedate=
    uploaddate=
    curl -s -L "https://api.ipsw.me/v4/device/$device_type?type=ipsw" -o tmp.json
    JSON_FILE=tmp.json
    if [[ ! -f "tmp.json" ]]; then
        error Unable get json,please check internat connection
    fi
    if [[ $1 == "ver" ]]; then
        version=$2
        if [[ "$device_type" == "iPod4,1" && "$version" == "4.1" ]]; then
            log Select version
            options=("8B117" "8B118")
            select_option "${options[@]}"
            selected_index=$?
            selected="${options[$selected_index]}"
            
            case $selected in
                "8B117" ) 
                    get_firmware_info build 8B117
                    return $?
                    ;;
                "8B118" ) 
                    get_firmware_info build 8B118
                    return $?
                    ;;
            esac
        fi
    elif [[ $1 == "build" ]]; then
        build=$2
    fi
    if [[ $1 == "ver" ]]; then
        buildid=$($jq -r ".firmwares[] | select(.version == \"$version\") | .buildid" "$JSON_FILE")
        filesize=$($jq -r ".firmwares[] | select(.version == \"$version\") | .filesize" "$JSON_FILE")
        url=$($jq -r ".firmwares[] | select(.version == \"$version\") | .url" "$JSON_FILE")
        sha1=$($jq -r ".firmwares[] | select(.version == \"$version\") | .sha1sum" "$JSON_FILE")
        sha256=$($jq -r ".firmwares[] | select(.version == \"$version\") | .sha256sum" "$JSON_FILE")
        md5=$($jq -r ".firmwares[] | select(.version == \"$version\") | .md5sum" "$JSON_FILE")
        signed=$($jq -r ".firmwares[] | select(.version == \"$version\") | .signed" "$JSON_FILE")
        releasedate=$($jq -r ".firmwares[] | select(.version == \"$version\") | .releasedate" "$JSON_FILE")
        uploaddate=$($jq -r ".firmwares[] | select(.version == \"$version\") | .uploaddate" "$JSON_FILE")
    elif [[ $1 == "build" ]]; then
        buildid="$build"
        filesize=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .filesize" "$JSON_FILE")
        url=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .url" "$JSON_FILE")
        sha1=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .sha1sum" "$JSON_FILE")
        sha256=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .sha256sum" "$JSON_FILE")
        md5=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .md5sum" "$JSON_FILE")
        signed=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .signed" "$JSON_FILE")
        releasedate=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .releasedate" "$JSON_FILE")
        uploaddate=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .uploaddate" "$JSON_FILE")
    fi
}

device_send_rdtar() {
    local target="/mnt1"
    if [[ $2 == "data" ]]; then
        target+="/private/var"
    fi
    log "Sending $1"
    $scp -P $ssh_port $jelbrek/$1 root@127.0.0.1:$target
    log "Extracting $1"
    $ssh -p $ssh_port root@127.0.0.1 "tar -xvf $target/$1 -C /mnt1; rm $target/$1"
}

device_iproxy() {
    local port=22
    log "Running iproxy for SSH..."
    if [[ -n $2 ]]; then
        port=$2
    fi
    if [[ $1 == "no-logging" && $debug_mode != 1 ]]; then
        "$dir/iproxy" $ssh_port $port -s 127.0.0.1 >/dev/null &
        iproxy_pid=$!
    else
        "$dir/iproxy" $ssh_port $port -s 127.0.0.1 &
        iproxy_pid=$!
    fi
    log "iproxy PID: $iproxy_pid"
    sleep 1
}

device_s5l8900xall() {
    local wtf_sha="cb96954185a91712c47f20adb519db45a318c30f"
    local wtf_saved="../saved/WTF.s5l8900xall.RELEASE.dfu"
    local wtf_patched="$wtf_saved.patched"
    local wtf_patch="../resources/patch/WTF.s5l8900xall.RELEASE.patch"
    local wtf_sha_local="$($sha1sum "$wtf_saved" 2>/dev/null | awk '{print $1}')"
    mkdir ../saved 2>/dev/null
    if [[ $wtf_sha_local != "$wtf_sha" ]]; then
        log "Downloading WTF.s5l8900xall"
        "$dir/pzb" -g "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu" -o WTF.s5l8900xall.RELEASE.dfu "http://appldnld.apple.com/iPhone/061-7481.20100202.4orot/iPhone1,1_3.1.3_7E18_Restore.ipsw"
        rm -f "$wtf_saved"
        mv WTF.s5l8900xall.RELEASE.dfu $wtf_saved
    fi
    wtf_sha_local="$($sha1sum "$wtf_saved" | awk '{print $1}')"
    if [[ $wtf_sha_local != "$wtf_sha" ]]; then
        error "SHA1sum mismatch. Expected $wtf_sha, got $wtf_sha_local. Please run the script again"
    fi
    rm -f "$wtf_patched"
    log "Patching WTF.s5l8900xall"
    $bspatch $wtf_saved $wtf_patched $wtf_patch
    log "Sending patched WTF.s5l8900xall (Pwnage 2.0)"
    $irecovery -f "$wtf_patched"
    checkmode DFU
    sleep 1
    device_srtg="$($irecovery -q | grep "SRTG" | cut -c 7-)"
    log "SRTG: $device_srtg"
    if [[ $device_srtg == "iBoot-636.66.3x" ]]; then
        device_argmode=
        device_type=$($irecovery -q | grep "PRODUCT" | cut -c 10-)
        device_model=$($irecovery -q | grep "MODEL" | cut -c 8-)
        device_model="${device_model%??}"
        device_pwnd="Pwnage 2.0"
    fi
}

device_fw_key_check() {
    # check and download keys for device_target_build, then set the variable device_fw_key (or device_fw_key_base)
    #remove download part , replace use unzip
    local key
    local build="$device_target_build"
    if [[ $1 == "base" ]]; then
        build="$device_base_build"
    elif [[ $1 == "temp" ]]; then
        build="$2"
    fi
    device_fw_dir=../saved/$device_type/$build
    local keys_path="."

    log "Checking firmware keys"
    if [[ $(cat "$keys_path/index.html" 2>/dev/null | grep -c "$build") != 1 ]]; then
        rm -f "$keys_path/index.html"
    fi
    if [[ ! -e "$keys_path/index.html" ]]; then
        cp ../resources/keys.zip .
        unzip -p keys.zip "Legacy-iOS-Kit-Keys-master/$device_type/$build/index.html" > index.html
    fi
    if [[ $1 == "base" ]]; then
        device_fw_key_base="$(cat index.html)"
    elif [[ $1 == "temp" ]]; then
        device_fw_key_temp="$(cat index.html)"
    else
        device_fw_key="$(cat index.html)"
    fi
}

patch_ibss() {
    # creates file pwnediBSS to be sent to device
    local build_id
    case $device_type in
        iPad1,1 | iPod3,1 ) build_id="9B206";;
        iPhone2,1 | iPod4,1 ) build_id="10B500";;
        iPhone3,[123] ) build_id="11D257";;
        * ) build_id="12H321";;
    esac
    if [[ -n $device_rd_build ]]; then
        build_id="$device_rd_build"
    fi
    download_comp $build_id iBSS
    device_fw_key_check temp $build_id
    local iv=$(echo $device_fw_key_temp | $jq -j '.keys[] | select(.image == "iBSS") | .iv')
    local key=$(echo $device_fw_key_temp | $jq -j '.keys[] | select(.image == "iBSS") | .key')
    log "Decrypting iBSS..."
    "$dir/xpwntool" iBSS iBSS.dec -iv $iv -k $key
    log "Patching iBSS..."
    "$dir/iBoot32Patcher" iBSS.dec pwnediBSS --rsa
    "$dir/xpwntool" pwnediBSS pwnediBSS.dfu -t iBSS
    cp pwnediBSS pwnediBSS.dfu ../saved/$device_type/
    log "Pwned iBSS saved at: saved/$device_type/pwnediBSS"
    log "Pwned iBSS img3 saved at: saved/$device_type/pwnediBSS.dfu"
}

download_comp() {
    # usage: download_comp [build_id] [comp]
    local build_id="$1"
    local comp="$2"
    ipsw_get_url $build_id
    download_targetfile="$comp.$device_model"
    if [[ $build_id != "12"* ]]; then
        download_targetfile+="ap"
    fi
    download_targetfile+=".RELEASE"

    if [[ -e "../saved/$device_type/${comp}_$build_id.dfu" ]]; then
        cp "../saved/$device_type/${comp}_$build_id.dfu" ${comp}
    else
        log "Downloading ${comp}..."
        "$dir/pzb" -g "Firmware/dfu/$download_targetfile.dfu" -o ${comp} "$ipsw_url"
        cp ${comp} "../saved/$device_type/${comp}_$build_id.dfu"
    fi
}

ipsw_get_url() {
    local device_fw_dir="../saved/${device_type}/urls"
    mkdir $device_fw_dir 2>/dev/null
    local build_id="$1"
    local version="$2"
    local url="$(cat "$device_fw_dir/$build_id/url" 2>/dev/null)"
    local url_local="$url"
    ipsw_url=
    log "Checking URL in $device_fw_dir/$build_id/url"
    if [[ $(echo "$url" | grep -c '<') != 0 || $url != *"$build_id"* ]]; then
        rm -f "$device_fw_dir/$build_id/url"
        url=
    fi
    if [[ $device_type == "iPod1,1" ]] && [[ $build_id == "5"* || $build_id == "7"* ]]; then
        url="https://invoxiplaygames.uk/ipsw/${device_type}_${version}_${build_id}_Restore.ipsw"
    elif [[ $device_type == "iPod2,1" && $build_id == "7"* ]]; then
        url="https://invoxiplaygames.uk/ipsw/${device_type}_${version}_${build_id}_Restore.ipsw"
    fi
    if [[ -z $url ]]; then
        log "Getting URL for $device_type-$build_id"
        local phone="OS" # iOS
        case $build_id in
            [23][0123456789]* | 7B405 | 7B500 ) :;;
            1[AC]* | [2345]* ) phone="Phone%20Software";; # iPhone Software
            7* ) phone="Phone%20OS";; # iPhone OS
        esac
        if [[ $device_type == "iPad"* ]]; then
            case $build_id in
                1[789]* | [23]* ) phone="PadOS";; # iPadOS
            esac
        fi
        rm -f tmp.json
        $aria2c "https://raw.githubusercontent.com/littlebyteorg/appledb/refs/heads/gh-pages/ios/i${phone};$build_id.json" -o tmp.json
        [[ $? != 0 ]] && $curl -L "https://raw.githubusercontent.com/littlebyteorg/appledb/refs/heads/gh-pages/ios/i${phone};$build_id.json" -o tmp.json
        url="$(cat tmp.json | $jq -r ".sources[] | select(.type == \"ipsw\" and any(.deviceMap[]; . == \"$device_type\")) | .links[0].url")"
        local url2="$(echo "$url" | tr '[:upper:]' '[:lower:]')"
        local build_id2="$(echo "$build_id" | tr '[:upper:]' '[:lower:]')"
        if [[ $(echo "$url" | grep -c '<') != 0 || $url2 != *"$build_id2"* ]]; then
            if [[ -n $url_local ]]; then
                url="$url_local"
                log "Using saved URL for this IPSW: $url"
                echo "$url" > $device_fw_dir/$build_id/url
                ipsw_url="$url"
                return
            fi
            if [[ $ipsw_isbeta != 1 ]]; then
                error "Unable to get URL for $device_type-$build_id"
            fi
        fi
        mkdir -p $device_fw_dir/$build_id 2>/dev/null
        echo "$url" > $device_fw_dir/$build_id/url
    fi
    ipsw_url="$url"
}

####others#####
clean() {
    kill $httpserver_pid $iproxy_pid $anisette_pid $sshfs_pid 2>/dev/null
    popd &>/dev/null
    rm -rf "$(dirname "$0")/tmp$$/"* "$(dirname "$0")/iP"*/ "$(dirname "$0")/tmp$$/" 2>/dev/null
    if [[ $platform == "macos" && $(ls "$(dirname "$0")" | grep -v tmp$$ | grep -c tmp) == 0 &&
          $no_finder != 1 ]]; then
        killall -CONT AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater
    fi
}

display_help() {
 print "Run ./sshrd32.sh use default version"
 print "Simplify Args"
 print "1. ./sshrd32.sh "ios ver/build ver"  use custom version,only support ios verion and ios build version"
 print "2. ./sshrd32.sh boot  boot ramdisk after make"
 print "3. ./sshrd32.sh ssh  connect ssh"
 print Args
 print "Add --version=“ramdisk build ver”/“ramdisk ver” use custom version,only support ios verion and ios build version"
 print "Add --device="iPhone/iPad/iPodx,x" custom device_type,without device check"
 print "Add --menu  directly access the menu"
 print "Add --make make ssh ramdisk only, without boot"
 print "Add --reboot reboot device in sshrd"
}

function select_option() {
    if [[ $menu_old == 1 ]]; then
        select opt in "$@"; do
            selected=$((REPLY-1))
            break
        done
        return $selected
    fi

    # clear input buffer to prevent error
    if (( bash_ver > 3 )); then
        while read -s -t 0.01 -n 1; do :; done
    else
        local old=$(stty -g)
        stty -icanon -echo min 0 time 1
        dd bs=1 count=1000 if=/dev/tty of=/dev/null 2>/dev/null
        stty "$old"
    fi

    # little helpers for terminal print control and key input
    ESC=$( printf "\033")
    cursor_blink_on()  { printf "$ESC[?25h"; }
    cursor_blink_off() { printf "$ESC[?25l"; }
    cursor_to()        { printf "$ESC[$1;${2:-1}H"; }
    print_option()     { printf "   $1  "; }
    print_selected()   { printf " ->$ESC[7m $1 $ESC[27m"; }
    get_cursor_row()   { IFS=';' read -sdR -p $'\E[6n' ROW COL; echo ${ROW#*[}; }
    key_input()        { read -s -n3 key 2>/dev/null >&2
                         if [[ $key = $ESC[A ]]; then echo up;    fi
                         if [[ $key = $ESC[B ]]; then echo down;  fi
                         if [[ $key = ""     ]]; then echo enter; fi; }

    # initially print empty new lines (scroll down if at bottom of screen)
    for opt; do printf "\n"; done

    # determine current screen position for overwriting the options
    local lastrow=`get_cursor_row`
    local startrow=$(($lastrow - $#))

    # ensure cursor and input echoing back on upon a ctrl+c during read -s
    trap "cursor_blink_on; stty echo; printf '\n'; exit" 2
    cursor_blink_off

    local selected=0
    while true; do
        # print options by overwriting the last lines
        local idx=0
        for opt; do
            cursor_to $(($startrow + $idx))
            if [ $idx -eq $selected ]; then
                print_selected "$opt"
            else
                print_option "$opt"
            fi
            ((idx++))
        done

        # user key control
        case `key_input` in
            enter) break;;
            up)    ((selected--));
                   if [ $selected -lt 0 ]; then selected=$(($# - 1)); fi;;
            down)  ((selected++));
                   if [ $selected -ge $# ]; then selected=0; fi;;
        esac
    done

    # cursor position back to normal
    cursor_to $lastrow
    printf "\n"
    cursor_blink_on

    return $selected
}

function select_opt {
    select_option "$@" 1>&2
    local result=$?
    echo $result
    return $result
}

function yesno() {
    local msg="是否继续?"
    if [[ -n $1 ]]; then
        msg="$1"
    fi
    if [[ $2 == 1 ]]; then
        msg+=" (Y/n): "
    else
        msg+=" (y/N): "
    fi
    local yesno=("No" "Yes") # default is "no" by default
    if [[ $2 == 1 ]]; then # default is "yes" if $2 is set to 1
        yesno=("Yes" "No")
    fi
    input "$msg"
    select_option "${yesno[@]}"
    local res=$?
    if [[ $2 == 1 ]]; then
        [[ $res == 0 ]] && return 1 || return 0
    fi
    return $res
}


debug_func() {
    log 1
    pause
}

trap clean EXIT
trap "exit 1" INT TERM
mkdir "$(dirname "$0")/tmp$$"
pushd "$(dirname "$0")/tmp$$" >/dev/null
mkdir ../saved 2>/dev/null
oscheck
set_ssh_config
set_path
for i in "$@"; do
    case "$i" in
        --version=* )
            device_rd_build_custom="${i#--version=}"
            ;;
        --ship-ssh-check )
            ship_ssh_check=1
            ;;
        --ship-boot )
            device_argmode=none
            ;;
        --ship-build-check )
            warning Without check the build process may cause errors.
            yesno Do you want to continue?
            if [[ $? == 1 ]]; then
                exit 1
            else
                ship_build_check=1
            fi
            ;;
        --menu )
            without_boot=1
            ssh_menu
            exit
            ;;
        --debug )
            debug=1
            ;;
        --debug-mode )
            debug_mode=1
            ;;
        --make )
            just_make=1
            device_argmode=none
            ;;
        --device=* )
           device_type="${i#--device=}"
            ;;
        --jailbreak | --jb )
            no_menu=1
            just_jailbreak=1
            ;;
        --hacktivate )
            no_menu=1
            just_hacktivate=1
            ;;
        --get-ios-ver )
            just_get_ios_ver=1
            no_menu=1
            ;;
        --help | --h )
            display_help
            exit 1
            ;;
         --hac-part-2 )
            no_menu=1
            just_part2=1
            ;;
        --reboot )
            device_iproxy
            $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
            exit 1
            ;;
        #legacy part,from SSHRD
        [0-9]*.[0-9]* )
            arg_l=1
            device_rd_build_custom="$i"
            device_argmode=none
            ;;
        [0-9]*[A-Za-z][0-9]* )
            arg_l=1
            device_rd_build_custom="$i"
            device_argmode=none
            ;;
        --boot | boot )
            just_boot=1
            nomenu=1
            ;;
        --ssh | ssh )
            device_iproxy
            ssh_message
            $ssh -p $ssh_port root@127.0.0.1
            exit 1
            ;;
    esac
done
main
#debug_func
popd >/dev/null