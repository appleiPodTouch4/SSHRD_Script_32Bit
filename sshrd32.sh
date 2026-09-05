#!/bin/bash
script_dir=".."
tmp="."
saved="../saved"
ssh_port=2222
isoscheck=1
jelbrek=../resources/Jailbreak
script_path=$(dirname "$0")/$(basename "$0")
enable_lastest_enter=0

if [[ $no_color != 1 ]]; then
    TERM=xterm-256color # fix colors for msys2 terminal
    color_R=$(tput setaf 9)
    color_G=$(tput setaf 10)
    color_B=$(tput setaf 12)
    color_Y=$(tput setaf 208)
    color_N=$(tput sgr0)
fi

print() {
    echo "${color_B}${1}${color_N}"
}

input() {
    echo "${color_Y}[Input] ${1}${color_N}"
}

log() {
    echo "${color_G}[Log] ${1}${color_N}"
}

warn() {
    echo "${color_Y}[WARN] ${1}${color_N}"
}

error() {
    echo -e "${color_R}[ERROR] ${1}\n${color_Y}${*:2}${color_N}"
}

pause() {
    if [[ -z $1 ]]; then
        input "Press Enter/Return to continue (or press Ctrl+C to cancel)"
    else
        input "$1"
    fi
    read -s
}

oscheck() {
    if [[ -f ../resources/current_platform ]]; then
        local local_platform_message=$(cat ../resources/current_platform 2>/dev/null)
    else
        local local_platform_message=""
    fi
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
                    warn "Using M-series chips may cause compatibility issues; please use with caution."
                    pause Press Enter to ignore this issue.  
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
                        error "Your macOS version is too old. Please upgrade to macOS High Sierra or later."
                        exit
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
                warn "There may be compatibility issues when using devices running macOS Monterey or later. Do you want to continue?"
                yesno continue?
                 if [[ $? == 1 ]]; then
                    :
                else
                    exit
                fi
            fi
            platform_message="macOS ${macos_name}($platform_arch)"
        elif [[ "$platform" == "linux" ]]; then
            warn The Linux version is still being adapted, and some features have not yet been fixed. Should we continue using it?
            pause Press Enter to continue.
            check_sudo
            #linux_part
            arch_path="linux/"
            linux_name=$(grep '^NAME=' /etc/os-release | cut -d'"' -f2)
            platform_message="${linux_name} ($platform_arch)"
            dir="../bin/linux"
            if [[ $linux_name != Ubuntu ]]; then
                error Support ubuntu only,your distro is unsupport.
                exit
            fi
        fi
    fi
    if [[ $platform_message != $local_platform_message ]]; then
        install_depends
    fi

}

linux_part() {
    if [[ -n $UBUNTU_CODENAME ]]; then
        case $UBUNTU_CODENAME in
            "jammy" | "kinetic"   ) ubuntu_ver=22;;
            "lunar" | "mantic"    ) ubuntu_ver=23;;
            "noble" | "oracular"  ) ubuntu_ver=24;;
            "plucky" | "questing" ) ubuntu_ver=25;;
        esac
        if [[ -z $ubuntu_ver ]]; then
            source /etc/upstream-release/lsb-release 2>/dev/null
            ubuntu_ver="$(echo "$DISTRIB_RELEASE" | cut -c -2)"
        fi
        if [[ -z $ubuntu_ver ]]; then
            ubuntu_ver="$(echo "$VERSION_ID" | cut -c -2)"
        fi
    elif [[ -e /etc/debian_version ]]; then
        debian_ver=$(cat /etc/debian_version)
        case $debian_ver in
            *"sid" | "kali"* ) debian_ver="sid";;
            * ) debian_ver="$(echo "$debian_ver" | cut -c -2)";;
        esac
    elif [[ $ID == "fedora" || $ID_LIKE == "fedora" || $ID == "nobara" ]]; then
        fedora_ver=$VERSION_ID
    fi
    if [[ $ID == "arch" || $ID_LIKE == "arch" || $ID == "artix" ]]; then
        distro="arch"
    elif (( ubuntu_ver >= 22 )) || (( debian_ver >= 12 )) || [[ $debian_ver == "sid" ]]; then
        distro="debian"
    elif (( fedora_ver >= 40 )); then
        distro="fedora"
        if [[ $(command -v rpm-ostree) ]]; then
            distro="fedora-atomic"
        fi
    elif [[ $ID == "opensuse-tumbleweed" ]]; then
        distro="opensuse"
    elif [[ $ID == "gentoo" || $ID_LIKE == "gentoo" || $ID == "pentoo" ]]; then
        distro="gentoo"
    elif [[ $ID == "void" ]]; then
        distro="void"
    elif [[ -n $ubuntu_ver || -n $debian_ver || -n $fedora_ver ]]; then
        error "Your distro version ($platform_ver - $platform_arch) is not supported. See the repo README for supported OS versions/distros"
    else
        warn "Your distro ($platform_ver - $platform_arch) is not detected/supported. See the repo README for supported OS versions/distros"
        print "* You may still continue, but you will need to install required packages and libraries manually as needed."
        sleep 5
        pause
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
    sudo="/usr/bin/sudo"
    if [[ $device_argmode == "none" ]]; then
        device_disable_sudoloop=1
        device_disable_usbmuxd=1
    fi
    if [[ $($sudo -V 2>&1) == "sudo-rs"* ]]; then
        if [[ -z $device_disable_sudoloop && -z $device_disable_usbmuxd ]]; then
            log "sudo-rs detected. Switching to sudo.ws"
        fi
        sudo+=".ws"
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
        a6meowing=""
        gaster=""
        iBoot32Patcher=""
        bruteforce_patcher=""
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
        bruteforce_patcher="sudo "
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
    gaster+=$dir/gaster
    iBoot32Patcher+=$dir/iBoot32Patcher
    bruteforce_patcher+=$dir/bruteforce_patcher
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
    afc+=$dir/afc_tool
    sha1sum="$(command -v shasum) -a 1"
}

prepare_udev_rules() {
    local owner="$1"
    local group="$2"
    echo "ACTION==\"add\", SUBSYSTEM==\"usb\", ATTR{idVendor}==\"05ac\", ATTR{idProduct}==\"122[27]|128[0-3]|1338\", OWNER=\"$owner\", GROUP=\"$group\", MODE=\"0660\" TAG+=\"uaccess\"" > 39-libirecovery.rules
}

install_depends() {
    rm -f "../resources/current_platform"
    touch "../resources/current_platform"
    if [[ $platform == "linux" ]]; then
        print "Install depends now"
        print "* Enter your user password when prompted"
        pause
        prepare_udev_rules usbmux plugdev
        if [[ -n $ubuntu_ver ]]; then
            sudo add-apt-repository -y universe
        fi
        sudo apt update
        sudo apt install -y \
            aria2 \
            ca-certificates \
            curl \
            git \
            libimobiledevice6 \
            libimobiledevice-utils \
            libssl3 \
            libzstd1 \
            openssh-client \
            patch \
            python3 \
            python3-pip \
            sshfs \
            unzip \
            usbmuxd \
            usbutils \
            vim-common \
            xxd \
            zenity \
            zip \
            zlib1g
        

        pip3 install pyimg4 pylibfdt-iOS

        if [[ $(command -v systemctl 2>/dev/null) ]]; then
            sudo systemctl enable --now udev systemd-udevd usbmuxd 2>/dev/null
        fi

        echo "$platform_message" > "../resources/current_platform"

        if [[ $platform == "linux" ]]; then
            if [[ $(command -v systemctl) ]]; then
                sudo systemctl enable --now systemd-udevd usbmuxd 2>/dev/null
            fi
            sudo cp 39-libirecovery.rules /etc/udev/rules.d/39-libirecovery.rules
            sudo chown root:root /etc/udev/rules.d/39-libirecovery.rules
            sudo chmod 0644 /etc/udev/rules.d/39-libirecovery.rules
            sudo udevadm control --reload-rules
            sudo udevadm trigger -s usb
        fi

        log "Install depends done! Please run the script again to proceed(if it has some errors,try to ignore it)"

        exit
    else
        echo "$platform_message" > "../resources/current_platform"
    fi
}

validate_build() {
    local raw_build="$1"
    [[ -z "$raw_build" ]] && return 1

    local last_char="${raw_build: -1}"

    local formatted_build
    formatted_build=$(printf '%s' "$raw_build" | tr '[:lower:]' '[:upper:]')
    if [[ "$last_char" =~ ^[a-z]$ ]]; then
        formatted_build="${formatted_build%?}${last_char}"
    fi

    if [[ "$formatted_build" =~ ^[0-9]+[A-Z]+[0-9]+[a-z]?$ ]]; then
        return 0
    fi

    return 1
}

set_ssh_config() {
    if [ -z "$1" ]; then
        cp ../resources/ssh_config .
        if [[ $(ssh -V 2>&1 | grep -c SSH_8.8) == 1 || $(ssh -V 2>&1 | grep -c SSH_8.9) == 1 ||
            $(ssh -V 2>&1 | grep -c SSH_9.) == 1 || $(ssh -V 2>&1 | grep -c SSH_1) == 1 ]]; then
            echo "    PubkeyAcceptedAlgorithms +ssh-rsa" >> ./ssh_config
        elif [[ $(ssh -V 2>&1 | grep -c SSH_6) == 1 ]]; then
            cat ssh_config | sed "s,Add,#Add,g" | sed "s,HostKeyA,#HostKeyA,g" > ssh_config
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

file_extract() {
    local archive="$1"
    local dest="$2"
    local arr=()
    if [[ $platform == "macos" ]]; then
        arr+=("-xzvf" "$archive")
        [[ -n $dest ]] && arr+=("-C" "$dest")
        tar "${arr[@]}"
        return
    fi
    arr+=("-o" "$archive")
    [[ -n $dest ]] && arr+=("-d" "$dest")
    unzip "${arr[@]}"
}

file_extract_from_archive() {
    local archive="$1"
    local file="$2"
    local dest="$3"
    [[ -z $dest ]] && dest=.
    local arr=()
    if [[ $platform == "macos" && $file != *"/"* ]]; then
        arr+=("-xzvOf" "$archive")
        arr+=("$file")
        tar "${arr[@]}" > "$dest/$file"
        return
    fi
    arr+=("-o" "-j" "$archive" "$file")
    [[ -n $dest ]] && arr+=("-d" "$dest")
    unzip "${arr[@]}"
}


checkmode() {
    if [[ $2 == irec ]] || [[ $platform == "linux" ]]; then
        local mode
        case $1 in
            nor )
            log "[*] Waiting for the device to enter Normal mode"
            while true; do
                device_ver=$($ideviceinfo -s 2>/dev/null | grep "ProductVersion:" | cut -d' ' -f2)
                if [[ $device_ver =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; then
                    break
                fi
                sleep 1
            done
            ;;
            rec | DFU | DFUall )
            if [[ $1 == rec ]]; then
                local mode="Recovery"
            elif [[ $1 == DFU ]]; then
                local mode="DFU"
            elif [[ $1 == DFUall ]]; then
                local mode="DFU"
            fi
            log "[*] Waiting for the device to enter $mode mode"
            while true; do
                device_mode="$($irecovery -q 2>/dev/null | grep -w "MODE" | cut -c 7-)"
                if [[ $device_mode == "$mode" ]]; then
                    break
                elif [[ $device_mode == "WTF" ]]; then
                    break
                fi
                sleep 1
            done
            ;;
        esac
    else
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
            log "[*] Waiting for the device to enter DFU mode"
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
    fi
    device_mode="$($irecovery -q 2>/dev/null | grep -w "MODE" | cut -c 7-)"
}

device_info() {
    if [[ -z $device_type ]]; then
        device_type=$($irecovery -q | grep -i "product" | awk -F': ' '{print $2}')
        device_protocol=$($ideviceinfo -s -k ProtocolVersion 2>/dev/null)
        if [[ $device_mode == "WTF" ]]; then
            local options=()
            local selected
            print "Select your device in the options below. Make sure to select correctly"
            options+=("iPhone2G" "iPod touch 1")
            [[ $device_protocol != 1 ]] && options+=("iPhone 3G")
            select_option "${options[@]}"
            selected="${options[$?]}"
            case $selected in
                "iPhone 2G"    ) device_type="iPhone1,1";;
                "iPhone 3G"    ) device_type="iPhone1,2";;
                "iPod touch 1" ) device_type="iPod1,1";;
            esac
        fi
    else
        if [[ $device_type =~ ^(iPhone|iPad|iPod)[1-9][0-9]*,[0-9]+$ ]]; then
            :
        else
            local try=1
            while true; do
                error Device type entered incorrectly,please please re-enter.
                device_type=""
                read $device_type
                if [[ $device_type =~ ^(iPhone|iPad|iPod)[1-9][0-9]*,[0-9]+$ ]]; then
                    break
                elif [[ $try == 5 ]]; then
                    error "Tried too many times,try to run the script again"
                    exit 1
                fi
                ((try++))
                sleep 1
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
        * ) error "Unsupport for 64Bit device,try to use(https://github.com/verygenericname/SSHRD_Script)"; exit;;
    esac
    device_ecid=$($idevicerestore -l 2>/dev/null | grep -i "ECID" | awk '{print $3}')
    
}

update() {
    log "Checking update"
    local local_ver=$(git rev-parse --short HEAD)
    local commit_info=$(curl -s "https://api.github.com/repos/appleiPodTouch4/SSHRD_Script_32Bit/commits?per_page=1" | $jq -r '.[0]')
    local sha=$(echo "$commit_info" | $jq -r '.sha')
    local latest=${sha:0:7}
    if [[ -z $local_ver || -z $latest ]]; then
        error Unable get version message,please check internet connection
        return
    fi
    if [[ $local_ver == $latest ]]; then
        log "It is already the latest commit,no upgrade required"
    else
        yesno "Newest commit is $latest. Do you want to update?" 1
        if [[ $? == 1 ]]; then
            cd ../
            if [[ -z $(command -v git) ]]; then
                error Please install git first
                return
            fi
            git fetch origin
            git reset --hard origin/main
            if [[ $(git rev-parse --short HEAD) == $latest ]]; then
                log "Update successfully,run ./sshrd32.sh again"
            else
                error Update failed,please check internet connection
                return
            fi
        else
            return
        fi
    fi
}

######pwn######
device_pwn() {
    local tool
    log "Getting device info and pwning... this may take a second"
    device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
    device_srtg="$($irecovery -q | grep "SRTG" | cut -c 7-)"
    if [[ -n $device_pwnd ]]; then
        log "Device seems to be already in pwned DFU mode"
        print "* Pwned: $device_pwnd"
        case $device_proc in
            [56] ) device_send_unpacked_ibss;;
        esac
        return
    elif [[ $device_mode == "DFU" && $device_boot4 != 1 && $device_srtg != "iBoot"* ]] &&
            [[ $device_proc == 4 || $device_proc == 5 || $device_proc == 6 ]]; then
        log "No SRTG for device in DFU mode! Already pwned iBSS mode?"
        print "* If your device is not in pwnDFU/kDFU mode, sending iBEC will fail."
        return
    fi

    if [[ $device_proc == 1 ]]; then
        device_s5l8900xall
        return
    fi

    if [[ $device_proc == 5 ]]; then
        log "Device is now in DFU mode. Now put your device in PWNED DFU mode using checkm8-a5."
        print "* For more details, go to: https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/checkm8-a5"
        pause
        log "Checking for device"
        device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
        if [[ -n $device_pwnd ]]; then
            log "Found device in pwned DFU mode."
            print "* Pwned: $device_pwnd"
        else
            warn "If you haven't sent pwnibss,press Ctrl+C to exit"
            warn "If you have sent pwnibss,press Enter to continue"
            pause
            device_send_unpacked_ibss
        fi
    fi

    if [[ $device_proc == 4 ]]; then
        tool="primepwn"
        if [[ $platform == "macos" && $device_type != "iPod2,1" ]]; then
            tool="ipwnder_lite"
        fi
    elif [[ $device_proc == 6 ]]; then
        tool="litera1n"
        if [[ $platform == "macos" ]]; then
            tool="ipwnder32"
            if [[ $platform_arch == "arm64" ]]; then
                tool="ipwnder_lite"
            fi
        elif [[ $device_type == "iPhone5,"* ]]; then
            tool="a6meowing"
        fi
    elif [[ $device_proc == 7 && $platform == "macos" && $platform_arch == "arm64" ]]; then
        tool="ipwnder_lite"
    fi
    log "Placing device to pwnDFU mode using $tool"
    print "* If pwning fails and gets stuck, you can press Ctrl+C to cancel, then re-enter DFU and retry."

    if [[ $tool == "a6meowing" ]]; then
        $a6meowing
        tool_pwned=$?
    elif [[ $tool == "litera1n" ]]; then
        kuroutadori_init
        kuroutadori_litera1n -p
        tool_pwned=$?
    elif [[ $tool == "ipwnder32" ]]; then
        "$dir/ipwnder32" -p --noibss
        tool_pwned=$?
    elif [[ $tool == "ipwnder_lite" ]]; then
        mkdir -p image3 ../saved/image3
        cp ../saved/image3/* image3/ 2>/dev/null
        "$dir/ipwnder" -pv
        tool_pwned=$?
        cp image3/* ../saved/image3/ 2>/dev/null
        log "gaster reset"
        $gaster reset
    elif [[ $tool == "primepwn" ]]; then
        $primepwn
        tool_pwned=$?
    fi
    sleep 1

    log "Checking for device"
    irec_pwned=$($irecovery -q | grep -c "PWND")
    device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
    # irec_pwned is instances of "PWND" in serial, must be 1
    # tool_pwned is error code of pwning tool, must be 0
    if [[ $irec_pwned != 1 && $tool_pwned != 0 ]]; then
        error "Pwn device failed,you can re-enter DFU and retry"
        exit
    fi
    if [[ -n $device_pwnd ]]; then
        log "Found device in pwned DFU mode."
        print "* Pwned: $device_pwnd"
        if [[ $device_proc == 6 ]]; then
            device_send_unpacked_ibss
        fi
    elif [[ $device_proc == 6 ]]; then
        device_srtg="$($irecovery -q | grep "SRTG" | cut -c 7-)"
        if [[ $device_srtg != "iBoot"* ]]; then
            log "Found device in pwned iBSS mode."
        else
            error "Pwn device failed,you can re-enter DFU and retry"
            exit
        fi
    else
        error "Pwn device failed,you can re-enter DFU and retry"
        exit
    fi
}


device_send_unpacked_ibss() {
    local pwnrec="pwned iBSS"
    local tool_pwned
    if [[ $device_boot4 == 1 ]]; then
        pwnrec="pwned recovery"
        cp iBSS.patched pwnediBSS
    else
        device_rd_build=
        patch_ibss
    fi
    if [[ $device_pwnd == *"wnder" ]]; then
        log "Sending packed iBSS..."
        $primepwn pwnediBSS.dfu
        tool_pwned=$?
    elif [[ $device_proc == 6 ]]; then
        log "gaster reset"
        $gaster reset
        sleep 1
        log "Sending iBSS..."
        $irecovery -f pwnediBSS.dfu
        tool_pwned=$?
    else
        log "Sending unpacked iBSS..."
        $primepwn pwnediBSS
        tool_pwned=$?
    fi
    rm -f pwnediBSS
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
    elif [[ $device_proc == 5 ]]; then
        error "Device failed to enter $pwnrec mode." \
              "* If you are using Arduino for checkm8-a5, make sure you are using my (LukeZGD) or synackuk fork of checkm8-a5. Do not use a1exdandy checkm8-a5."
    else
        error "Device failed to enter $pwnrec mode."
    fi
}

device_s5l8900xall() {
    local wtf_sha="cb96954185a91712c47f20adb519db45a318c30f"
    local wtf_saved="../saved/patches/WTF.s5l8900xall.RELEASE.dfu"
    local wtf_patched="$wtf_saved.patched"
    local wtf_patch="../resources/patch/WTF.s5l8900xall.RELEASE.patch"
    local wtf_sha_local="$($sha1sum "$wtf_saved" 2>/dev/null | awk '{print $1}')"
    mkdir ../saved 2>/dev/null
    mkdir ../saved/patches 2>/dev/null
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

kuroutadori_init() {
    local comm="https://sep.lol/files/legacypreviews/v1.0.2/a3ad4e6e525393239b3ac4ad58499f25a336b03b97cba6fba4f3a273c8505653548f2c7ad37fc18b1e69e0fddb5b73a3/kurouta_dori_v1.0.2_75aab959_legacymacosx.tar.gz"
    local sha1="61d3d964d194fd9a2084045c3cd95dc3e7920015"
    kuroutadori="kuroutadori_${platform}"
    if [[ $device_argmode == 1 ]]; then
        psudo="$sudo"
    else
        psudo="/usr/bin/sudo"
    fi
    if [[ $platform == "linux" ]]; then
        kuroutadori+="-${platform_arch}"
        comm="https://sep.lol/files/legacypreviews/v1.0.2/37daa814d98a38640813527be6c82ec1ee0561923b543c2290a0d519e9b2e7f7b73147a26e38d7f8a849fd70e0713125/kurouta_dori_v1.0.2_75aab959_linux-amd64.tar.gz"
        sha1="6d801a59979c64ff73015a8bfc950518dc043525"
        if [[ $platform_arch == "arm64" ]]; then
            comm="https://sep.lol/files/legacypreviews/v1.0.2/e04e9d27bcb8339e2e876ad92cc751b1e679b1ce91d2807b13ff1bc820d97349ee5ce5d1c58e61ec062e1a6b7bc2b726/kurouta_dori_v1.0.2_75aab959_linux-arm64.tar.gz"
            sha1="1dea1e3e5c7ca921ea6f6380ed0261d9c36a0165"
        fi
    fi
    if [[ ! -s ../saved/$kuroutadori/bin/litera1n || $(cat ../saved/$kuroutadori/sha1check) != "$sha1" ]]; then
        rm -rf ../saved/$kuroutadori
        file_download "$comm" kuroutadori.tar.gz $sha1
        mkdir -p ../saved/$kuroutadori
        tar -xvf kuroutadori.tar.gz -C ../saved/$kuroutadori
        echo "$sha1" > ../saved/$kuroutadori/sha1check
    fi
    kuroutadori="$psudo ../saved/$kuroutadori/bin"
}

kuroutadori_litera1n() {
    local tool_pwned
    print "* If pwning fails, try to rerun the script with --ra1n-timeout=1000000 (or adjust the value as needed)"
    print "* If it gets stuck at \"checkm8 setup stage\", unplug and replug the device."
    print "* If it gets stuck at \"Checkmate?\", press Ctrl+C to cancel, then re-enter DFU and retry."
    for i in {1..3}; do
        log "Running litera1n (attempt $i): $kuroutadori/litera1n $1"
        $kuroutadori/litera1n $1
        tool_pwned=$?
        [[ $tool_pwned == 0 || $tool_pwned == 30 ]] && break
    done
    return $tool_pwned
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
    local local_build_id
    local files
    local arch
    local res
    local mode=$main_argmode
    local mode1=$other_argmode
    local rec=2
    all_flash="Firmware/all_flash/all_flash.${device_model}ap.production"
    local bundle="../resources/firmware/FirmwareBundles/Down_"

    if [[ $1 == "setnvram" ]]; then
        rec=$2
    fi

    comps+=("RestoreRamdisk")
    case $device_type in
        iPhone1,[12] | iPod1,1 ) device_target_build="7E18"; device_target_vers="3.1.3";;
        iPod2,1 ) device_target_build="8C148";;
        iPod3,1 | iPad1,1 ) device_target_build="9B206";;
        iPhone2,1 | iPod4,1 ) device_target_build="10B500";;
        iPhone5,[34] ) device_target_build="11D257";;
        * ) device_target_build="10B329";;
    esac
    if [[ $mode1 == "ipsw" ]]; then
        if [[ -n $device_rd_ver ]]; then
            if [[ "$device_rd_ver" == [0-9].* ]]; then
                if [[ $device_rd_ver == [123].* ]]; then
                    local i="iPhone"
                else
                    local i="i"
                fi
                log "Select ${i}OS${device_rd_ver} ipsw to make ssh ramdisk"
            else
                log "Select $device_rd_ver ipsw to make ssh ramdisk"
            fi
        else
            log Select "$device_target_build ipsw to make ssh ramdisk"
        fi
        local try=0
        while true; do
            ipsw_path="$($zenity --file-selection --file-filter='IPSW | *.ipsw' --title="Select IPSW file(s)")"
            get_ipsw_info target $ipsw_path
            if [[ -z $ipsw_path || $ipsw_select_wrong == 1 ]]; then
                error You seleted wrong ipsw,please selet again
                ((try++))
                if [[ $try == 5 ]]; then
                    error "You've selected the wrong IPSW too many times. Try downloading it again."
                    exit
                fi
            else
                if [[ $device_ipsw_vers == [12].* ]]; then
                    warn "This version cannot make ramdisk(it has something wrong),please select iOS3+ IPSW"
                    exit
                else
                    case $device_ipsw_build in
                        *[bcdefgkmpquv] )
                            log "Beta IPSW detected, skip verification"
                            ipsw_isbeta=1
                        ;;
                    esac
                    break
                fi
            fi
        done
    fi

    if [[ $device_proc == "1" ]]; then
        if [[ -n $device_rd_ver ]]; then
            if [[ $device_type == "iPhone1,2" ]]; then
                validate_build $device_rd_ver
                if [[ $? == 0 ]]; then
                    case $device_rd_ver in
                        "7E18" | "8B117" | "8C148" ) :;;
                        * ) 
                        warn "This version of ramdisk is unsupport for $device_type" 
                        log "Making $device_target_build ramdisk instead"
                        device_rd_ver=""
                        ;;
                    esac
                else
                    case $device_rd_ver in
                        "3.1.3" | "4.1" | "4.2.1" ) :;;
                        * ) 
                        warn "This version of ramdisk is unsupport for $device_type" 
                        log "Making $device_target_build ramdisk instead"
                        device_rd_ver=""
                        ;;
                    esac
                fi
            else
                warn "$device_type is not supported for define custom ramdisk version"
                log "Making $device_target_build ramdisk instead"
                device_rd_ver=""
            fi
        fi
    elif [[ $device_type == "iPod2,1" ]]; then
        validate_build $device_rd_ver
        if [[ $? == 0 ]]; then
            case $device_rd_ver in
                "7C145" | "7D11" | "7E18" | "8A293" | "8A400" | "8B117" | "8C148" ) :;;
                * ) 
                warn "This version of ramdisk is unsupport for $device_type" 
                log "Making $device_target_build ramdisk instead"
                device_rd_ver=""
                ;;
            esac
        else
            case $device_rd_ver in
                "3.1.1" | "3.1.2" | "3.1.3" | "4.0" | "4.0.2" | "4.1" | "4.2.1" ) :;;
                * ) 
                warn "This version of ramdisk is unsupport for $device_type" 
                log "Making $device_target_build ramdisk instead"
                device_rd_ver=""
                ;;
            esac
        fi
    fi



    if [[ -n $device_rd_ver ]]; then
        get_firmware_info $device_rd_ver
        device_target_build=$firmware_buildid
        device_target_vers=$firmware_version
    elif [[ -n $device_rd_ver ]] && [[ -n $ipsw_path ]]; then
        get_firmware_info $device_rd_ver
        if [[ $device_ipsw_build != $firmware_buildid ]]; then
            warn "The IPSW build is different from what you defined."
            yesno "Do you want to continue using the IPSW build?"
            if [[ $? == 1 ]]; then
                device_target_build=$device_ipsw_build
            else
                return
            fi
        fi
    else
        get_firmware_info $device_target_build
        device_target_vers=$firmware_version
    fi

    device_fw_key_check
    ipsw_url=$firmware_url
    version=$device_target_vers
    build_id=$device_target_build
    bundle+="${device_type}_${version}_${build_id}.bundle"
    print "*Ramdisk version:$version($build_id)*"
    ramdisk_path="../saved/$device_type/ramdisk_$build_id"
    
    
    if [[ -d $ramdisk_path ]]; then
        local ramdisk_files=("Ramdisk.dmg" "DeviceTree.dec" "Kernelcache.dec")
        for files in $ramdisk_files; do
            if [[ ! -f $ramdisk_path/$files ]]; then
                warn "$files missed,redownload"
                pause
                rm -rf $ramdisk_path
                break
            fi
        done
        if [[ -d $ramdisk_path ]]; then
            if [[ $mode != "bruteforce" ]] || [[ $mode == "bruteforce" ]] && [[ -e $ramdisk_path/KernelcacheB.dec ]] && [[ -e $ramdisk_path/RamdiskB.dmg ]]; then
                log "Ramdisk exist"
                ramdisk_boot
                return
            fi
        fi
    fi  

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
                [12345789]* | 10* | 11* ) hwmodel+="ap";;
            esac
            case $getcomp in
                "iBSS" | "iBEC" ) name="$getcomp.$hwmodel.RELEASE.dfu";;
                "DeviceTree" )    
                    if [[ $plist_legacy == 1 && $device_ipsw_build == 3* ]]; then
                        name="$getcomp.${device_model}ap.img2"
                    else
                        name="$getcomp.${device_model}ap.img3"
                    fi
                    ;;
                "Kernelcache" ) 
                    if [[ $plist_legacy == 1 && $device_ipsw_build == 3* ]]; then
                        name="kernelcache.release.*"
                    else  
                        name="kernelcache.release.$hwmodel"
                    fi
                    ;;
            esac
        fi
        case $getcomp in
            "RestoreRamdisk" )
                case $name in
                    *.dmg.dmg )
                        name=$(basename $name .dmg)
                    ;;
                esac
                ;;
        esac
        log "$getcomp"
        if [[ -s $ramdisk_path/$name ]]; then
            cp $ramdisk_path/$name .
        elif [[ -n $ipsw_path ]]; then
            unzip -p $ipsw_path "${path}$name" > $name
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

    log "Patch RestoreRamdisk"
    "$dir/xpwntool" RestoreRamdisk.dec Ramdisk.raw
    "$dir/hfsplus" Ramdisk.raw grow 32000000
    "$dir/hfsplus" Ramdisk.raw untar ../resources/sbplist.tar


    if [[ $device_proc == 1 || $device_type == "iPod2,1" ]]; then
        "$dir/hfsplus" Ramdisk.raw untar ../resources/ssh_old.tar
        "$dir/xpwntool" Ramdisk.raw Ramdisk.dmg -t RestoreRamdisk.dec
        log "Patch iBSS"
        $bspatch iBSS.dec iBSS.patched $bundle/iBSS.${device_model}ap.RELEASE.patch
        "$dir/xpwntool" iBSS.patched iBSS -t iBSS.orig
        log "Patch Kernelcache"
        mv Kernelcache.dec Kernelcache0.dec
        $bspatch Kernelcache0.dec Kernelcache.patched $bundle/kernelcache.release.patch
        "$dir/xpwntool" Kernelcache.patched Kernelcache.dec -t Kernelcache.orig $decrypt
        rm DeviceTree.dec
        mv DeviceTree.orig DeviceTree.dec
    else
        "$dir/hfsplus" Ramdisk.raw untar ../resources/ssh.tar
        if [[ $mode == "jailbreak" && $device_vers == "8"* ]]; then
            "$dir/hfsplus" Ramdisk.raw untar ../resources/jailbreak/daibutsu/bin.tar
        fi
        "$dir/hfsplus" Ramdisk.raw mv sbin/reboot sbin/reboot_bak
        "$dir/hfsplus" Ramdisk.raw mv sbin/halt sbin/halt_bak

        if [[ $mode == "bruteforce" ]]; then
            cp Ramdisk.raw RamdiskB.raw
            case $build_id in
                    "12"* | "13"* | "14"* )
                    log "Patching restored_external..."
                    "$dir/hfsplus" RamdiskB.raw mv usr/local/bin/restored_external usr/local/bin/restored_external.real
                    "$dir/hfsplus" RamdiskB.raw add ../resources/bruteforce/setup.sh usr/local/bin/restored_external
                    "$dir/hfsplus" RamdiskB.raw chmod 755 usr/local/bin/restored_external
                    "$dir/hfsplus" RamdiskB.raw chown 0:0 usr/local/bin/restored_external
                ;;
            esac
            log "Patching bruteforce"
            "$dir/hfsplus" RamdiskB.raw add ../resources/bruteforce/restored_external usr/local/bin/restored_external.sshrd
            "$dir/hfsplus" RamdiskB.raw chmod 755 usr/local/bin/restored_external.sshrd
            "$dir/hfsplus" RamdiskB.raw chown 0:0 usr/local/bin/restored_external.sshrd
            "$dir/hfsplus" RamdiskB.raw add ../resources/bruteforce/bruteforce usr/bin/bruteforce
            "$dir/hfsplus" RamdiskB.raw chmod 755 usr/bin/bruteforce
            "$dir/hfsplus" RamdiskB.raw chown 0:0 usr/bin/bruteforce
            "$dir/xpwntool" RamdiskB.raw RamdiskB.dmg -t RestoreRamdisk.dec
            cp RamdiskB.dmg $ramdisk_path 2>/dev/null
        fi

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

        log "Patch iBSS"
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
            log "Patch iBEC"
            "$dir/xpwntool" iBEC.dec iBEC.raw
            local bootarg="rd=md0 -v amfi=0xff amfi_get_out_of_my_way=1 cs_enforcement_disable=1 pio-error=0"
            "$dir/iBoot32Patcher" iBEC.raw iBEC.patched --rsa --debug -b "$bootarg"
            "$dir/xpwntool" iBEC.patched iBEC -t iBEC.dec
        fi
    fi

    if [[ $device_boot4 == 1 && $build_id == "8E"* ]]; then
        log "Patch Kernelcache"
        mv Kernelcache.dec Kernelcache0.dec
        "$dir/xpwntool" Kernelcache0.dec Kernelcache.raw
        $bspatch Kernelcache.raw Kernelcache.patched ../resources/patch/kernelcache.release.${device_model}.${build_id}.patch
        "$dir/xpwntool" Kernelcache.patched Kernelcache.dec -t Kernelcache0.dec
    fi

    if [[ $mode == "bruteforce" ]]; then
        log "Patch Kernelcache"
        local cpu_arch="armv7"
        [[ $device_proc == 1 || $device_type == "iPod2,1" ]] && local cpu_arch="armv6"
        cut_os_vers $version
        "$dir/xpwntool" Kernelcache.dec Kernelcache.raw
        $bruteforce_patcher Kernelcache.raw --os $major_ver --arch $cpu_arch
        if [[ $? == 1 ]]; then
            error "Patching kernelcache failed"
            exit 1
        fi
        "$dir/xpwntool" Kernelcache.raw.patched KernelcacheB.dec -t Kernelcache.dec
        if [[ ! -e KernelcacheB.dec ]]; then
            error "Patching kernelcacheB.dec failed"
            exit 1
        fi
        cp KernelcacheB.dec $ramdisk_path 2>/dev/null
    fi
    pause

    mv iBSS iBEC DeviceTree.dec Kernelcache.dec Ramdisk.dmg $ramdisk_path 2>/dev/null

    if [[ $build_id == "7"* || $build_id == "8"* ]] && [[ $device_type != "iPad"* ]]; then
        if [[ ! -f $ramdisk_path/DeviceTree.dec ]] || [[ ! -f $ramdisk_path/Kernelcache.dec ]] || [[ ! -f $ramdisk_path/Ramdisk.dmg ]] || [[ ! -f $ramdisk_path/iBSS ]]; then
            error "Make ramdisk failed,some files missed"
            exit 1
        fi
    elif [[ ! -f $ramdisk_path/DeviceTree.dec ]] || [[ ! -f $ramdisk_path/Kernelcache.dec ]] || [[ ! -f $ramdisk_path/Ramdisk.dmg ]] || [[ ! -f $ramdisk_path/iBSS ]] || [[ ! -f $ramdisk_path/iBEC ]]; then
        error "Make ramdisk failed,some files missed"
        exit 1
    fi
    log "Done creating SSH ramdisk files: saved/$device_type/ramdisk_$build_id"
    if [[ $device_argmode == "none" ]]; then
        log "Use ./sshrd32.sh boot to boot ramdisk"
        return
    else
        ramdisk_boot
        return
    fi
}

ramdisk_boot() {
    local mode=$main_argmode
    local mode1=$other_argmode
    local ramdisk_path="../saved/$device_type/ramdisk_$device_target_build"
    yesno "Do you want to boot ramdisk?"
    if [[ $? != 1 ]]; then
        return
    fi
    

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
    if [[ $build_id != "7"* && $build_id != "8"* ]]; then
        if [[ $device_proc != 1 ]]; then
            log "Sending iBEC..."
            $irecovery -f $ramdisk_path/iBEC
            if [[ $device_pwnrec == 1 ]]; then
                $irecovery -c "go"
            fi
        fi
    fi
    sleep 3
    checkmode rec
    log "Sending ramdisk..."
    if [[ $mode == "bruteforce" ]]; then
        $irecovery -f $ramdisk_path/RamdiskB.dmg
    else
        $irecovery -f $ramdisk_path/Ramdisk.dmg
    fi
    log "Running ramdisk"
    $irecovery -c "getenv ramdisk-delay"
    $irecovery -c ramdisk
    sleep 2
    log "Sending DeviceTree..."
    $irecovery -f $ramdisk_path/DeviceTree.dec
    log "Running devicetree"
    $irecovery -c devicetree
    log "Sending KernelCache..."
    if [[ $mode == "bruteforce" ]]; then
        $irecovery -f $ramdisk_path/KernelcacheB.dec
    else
        $irecovery -f $ramdisk_path/Kernelcache.dec
    fi
    $irecovery -c bootx
    log "Booting, please wait..."
    sleep 6

    if [[ -n $1 ]]; then
        device_iproxy
    else
        device_iproxy no-logging
    fi
    local found
    log "Waiting for device..."
    print "* You may need to unplug and replug your device."
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
    
    case $mode in
        "get_ios_ver" ) check_iosvers;;
        "jailbreak" ) jailbreak_sshrd;;
        "hacktivate" ) device_hacktivate;;
        "hacktivate_part2" ) device_hacktivate_part2;;
        * ) ssh_menu;;
    esac

    if [[ $main_argmode == "exit" ]]; then
        exit
    else
        lastest_enter
    fi

    return

}


lastest_enter() {
    local options=()
    local selected
    options+=("Go to Menu")
    options+=("Reboot")
    log "What do you want to do next?"
    select_option "${options[@]}"
    selected="${options[$?]}"
    if [[ $selected == "Go to Menu" ]]; then
        ssh_menu
    else
        $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"; exit
    fi
}


ssh_menu() {
    local options=()
    local selected
    local mode
    device_iproxy
    if [[ $debug == 1 ]]; then
        pause
    fi
    clear
    print  "*** SSHRD_Script_32Bit ***"
    print  "- $platform_message -"
    print  "- Script by MrY0000 -"
    print  "- Thanks LuckZGD Setup.app -"
    print  "- Forked from Legacy-iOS-Kit(https://github.com/LukeZGD/Legacy-iOS-Kit) -"
    input "Select option:"
    options+=("SSH Connection")
    options+=("Jailbreak")
    options+=("Check iOS Version")
    options+=("Hacktivate Device")
    options+=("Unlimited password attempts")
    options+=("Backup Activation Files")
    options+=("Restore Activation Files")
    options+=("Backup Baseband Files")
    options+=("Restore Baseband Files")
    options+=("Fix Disable")
    if [[ $device_type == iPod* ]]; then
        options+=("Enable Battery persentage")
    fi
    options+=("Clear NVRAM")
    options+=("Reboot")
    options+=("Exit")
    select_option "${options[@]}"
    selected="${options[$?]}"
        case $selected in
            "SSH Connection")
                ssh_message ; $ssh -p $ssh_port root@127.0.0.1;;
            "Hacktivate Device") mode="hacktivate";;
            "Jailbreak") mode="jailbreak";;
            "Unlimited password attempts") mode="password";;
            "Backup Activation Files") mode="ac_bk";;
            "Restore Activation Files") mode="ac_re";;
            "Backup Baseband Files") mode="bb_bk";;
            "Restore Baseband Files") mode="bb_re";;
            "Check iOS Version") mode="check_iosvers" ;;
            "Fix Disable") mode="fix_disable";;
            "Enable Battery persentage") mode="battery";;
            "Clear NVRAM")
                log Clear NVRAM
                $ssh -p $ssh_port root@127.0.0.1 "nvram -c" ; pause;;
            "Reboot")
                log Rebooting
                $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"; main_argmode="exit";;
            "Exit" ) main_argmode="exit" ;;
        esac
    case $mode in
        "hacktivate" ) device_hacktivate;;
        "jailbreak" ) jailbreak_sshrd;;
        "password" ) device_password;;
        "ac_bk" ) device_rebk backup ac;;
        "ac_re" ) device_rebk restore ac;;
        "bb_bk" ) device_rebk backup bb;;
        "bb_re" ) device_rebk restore bb;;
        "battery") device_battery;;
    esac
    pause

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
        print "* iOS Version: $device_vers ($device_build)"
        if [[ $1 != nopause ]]; then
            pause
            return
        fi
    else
        error "Unable get iOS Version"
        if [[ $1 != nopause ]]; then
            pause
            return 1
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
    local mode=$main_argmode
    local mode1-$other_argmode
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
        warn "Your device seems to be already jailbroken. Cannot continue."
        if [[ $mode == "jailbreak" ]]; then
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
                * ) untether="panguaxe.tar";;
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
            warn "Something wrong happened. Failed to get iOS version."
            if [[ $just_jailbreak == 1 ]]; then
                $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
            else
                pause
                return
            fi
        ;;
    esac

    if [[ -z $untether ]]; then
        warn "iOS $vers is not supported for jailbreaking with SSHRD."
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
    main_argmode="exit"
}

device_rebk() {
    local mode=$1
    local option=$2
    local files
    local saved
    if [[ -z $device_ecid ]]; then
        local device_ecid=$(date +%Y-%m-%d-%H%M)
    fi
    check_iosvers
    if [[ -z $device_vers ]]; then
        return
    else
        cut_os_vers $device_vers
    fi
    $ssh -p $ssh_port root@127.0.0.1 "umount /mnt1"
    $ssh -p $ssh_port root@127.0.0.1 "umount /mnt2"
    log "Mount file systems"
    if [[ $mode == "restore" ]]; then
        $ssh -p $ssh_port root@127.0.0.1 "mount.sh pv"
    else
        $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
    fi
    case $option in
        "ac" )
        if [[ $mode == "restore" ]]; then
            local tar
            local tar_name
            log "Restore activate files"
            tar="$($zenity --file-selection --file-filter='TAR | *.tar' --title="Select TAR file(s)")"
            if [[ -z $tar ]]; then
                warn "No tar file selected."
                return
            fi
            tar_name=$(basename "$tar")
            if [[ $(tar -tf $tar | grep -c "_record.plist") == 0 ]]; then
                warn "Activation record not found in tar"
                yesno
                if [[ $? != 1 ]]; then
                    return
                fi
            fi
            log "Sending $tar_name"
            $scp -P $ssh_port $tar root@127.0.0.1:/mnt1
            log "Extracting $tar_name"
            $ssh -p $ssh_port root@127.0.0.1 "tar -xvf /mnt1/$tar_name -C /mnt1; rm /mnt1/$tar_name"
            log "Done,activation files restored"
        else
            local dmp2="root/Library/Lockdown"
            local new
            case $major_ver in
                [34567]* ) dmps="$dmp2";;
                8* | 9.[012]* ) dmps="mobile/Library/mad";;
                * )
                    dmps="containers/Data/System/*/Library/activation_records"
                    dmp2+="/activation_records"
                    new=1
                ;;
            esac
            local tmp="/mnt2/tmp"
            local var="/mnt2"

            log "Creating activation.tar"
            $ssh -p $ssh_port root@127.0.0.1 "mkdir -p $tmp/private/var/$dmp2; cp -R /mnt2/$dmps/* $tmp/private/var/$dmp2"
            if [[ $new == 1 ]]; then
                $ssh -p $ssh_port ${ssh_user}@127.0.0.1 "cp /mnt2/containers/Data/System/*/Library/internal/data_ark.plist $tmp/private/var/root/Library/Lockdown"
            fi

            local actrec_files=(
                "mobile/Media/iTunes_Control/iTunes/IC-Info.sidv"
                "mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv"
                "wireless/Library/Preferences/com.apple.commcenter.plist"
            )
            local ssh_user="root"
            $ssh -p "$ssh_port" "${ssh_user}@127.0.0.1" "
            mkdir -p $tmp/private/var
            cd $tmp/private/var
            mkdir -p \
                mobile/Media/iTunes_Control/iTunes \
                mobile/Library/FairPlay/iTunes_Control/iTunes \
                mobile/Library/Preferences \
                wireless/Library/Preferences

            cd $tmp
            for f in ${actrec_files[*]}; do
                cp \"$var/\$f\" \"private/var/\$f\"
            done

            chown -R 501:501 private/var/mobile
            chown -R 25:25 private/var/wireless

            tar -cvf \"activation.tar\" private
            "
            $scp -P $ssh_port root@127.0.0.1:$tmp/activation.tar .
            if [[ -e activation.tar ]] && [[ $(tar -tf activation.tar | grep -c "_record.plist") != 0 ]]; then
                log "Done,activation files saved at saved/$device_type/activation-$device_type-$device_vers-$device_ecid.tar"
                cp activation.tar ../saved/$device_type/activation-$device_type-$device_vers-$device_ecid.tar
            else
                warn "Activation record not found in tar. Will not save activation dump."
                pause
            fi
        fi
        ;;
        "bb" )
        case $device_type in
            iPhone[45]* | iPad2,[67] | iPad3,[56] ) :;;
            * ) log "This device has no baseband(or too old) and requires no backup or restore."; return;;
        esac
        if [[ $mode == "restore" ]]; then
            local tar
            local tar_name
            log "Restore baseband files"
            tar="$($zenity --file-selection --file-filter='TAR | *.tar' --title="Select TAR file(s)")"
            if [[ -z $tar ]]; then
                warn "No tar file selected."
                return
            fi
            tar_name=$(basename "$tar")
            if [[ $(tar -tf $tar | grep -c "bbticket.der") == 0 ]]; then
                warn "Bbticker.der not found in tar"
                yesno
                if [[ $? != 1 ]]; then
                    return
                fi
            fi
            log "Sending $tar_name"
            $scp -P $ssh_port $tar root@127.0.0.1:/mnt1
            log "Extracting $tar_name"
            $ssh -p $ssh_port root@127.0.0.1 "tar -xvf /mnt1/$tar_name -C /mnt1; rm /mnt1/$tar_name"
            log "Done,baseband files restored"
        else
            local bb2="Mav5"
            local root="/mnt1/"
            local root2=
            local tmp="/mnt2/tmp"
            case $device_type in
                iPhone4,1 ) bb2="Trek";;
                iPhone5,[34] ) bb2="Mav7Mav8";;
            esac
            log "Creating baseband.tar"
            case $device_vers in
                5* ) $scp -P $ssh_port root@127.0.0.1:${root}usr/standalone/firmware/$bb2-personalized.zip .;;
                6* ) $scp -P $ssh_port root@127.0.0.1:${root}usr/local/standalone/firmware/Baseband/$bb2/$bb2-personalized.zip .;;
            esac
            case $device_vers in
                [56]* )
                    mkdir -p usr/local/standalone/firmware/Baseband/$bb2
                    file_extract $bb2-personalized.zip usr/local/standalone/firmware/Baseband/$bb2
                    cp $bb2-personalized.zip usr/local/standalone/firmware/Baseband/$bb2
                ;;
                * )
                    $ssh -p $ssh_port root@127.0.0.1 "cd $root; tar -cvf $tmp/baseband.tar ${root2}usr/local/standalone/firmware"
                    $scp -P $ssh_port root@127.0.0.1:$tmp/baseband.tar .
                    if [[ ! -s baseband.tar ]]; then
                        error "Dumping baseband tar failed. Please run the script again" \
                            "* If your device is on iOS 9 or newer, make sure to set the version of the SSH ramdisk correctly."
                    fi
                    tar -xvf baseband.tar -C .
                    rm baseband.tar
                    pushd usr/local/standalone/firmware/Baseband/$bb2 >/dev/null
                    zip -r0 $bb2-personalized.zip *
                    file_extract $bb2-personalized.zip
                    popd >/dev/null
                ;;
            esac
            if [[ $device_type == "iPhone4,1" ]]; then
                mkdir -p usr/standalone/firmware
                cp usr/local/standalone/firmware/Baseband/$bb2/$bb2-personalized.zip usr/standalone/firmware
            fi
            tar -cvf baseband-$device_ecid.tar usr
            if [[ $(tar -tf baseband-$device_ecid.tar | grep -c "bbticket.der") != 0 ]]; then
                cp baseband-$device_ecid.tar ../saved/$device_type/baseband-$device_type-$device_vers-$device_ecid.tar
                log "Done,baseband files saved at saved/$device_type/baseband-$device_type-$device_vers-$device_ecid.tar"
            else
                warn "bbticket not found in tar. Will not save baseband dump."
            fi
        fi
        ;;
    esac

}

device_raw_dump() {
    if [[ $device_proc == 4 && $device_pwnrec != 1 ]]; then
        patch_ibss
        log "Sending iBSS..."
        $irecovery -f pwnediBSS.dfu
    fi
    sleep 2
    patch_ibec
    log "Sending iBEC..."
    $irecovery -f pwnediBEC.dfu
    if [[ $device_pwnrec == 1 ]]; then
        $irecovery -c "go"
    fi
    sleep 3
    checkmode rec
    log "Dumping raw dump now"
    (echo -e "/send ../resources/payload\ngo blobs\n/exit") | $irecovery2 -s
    $irecovery2 -g dump.raw
    log "Rebooting device"
    $irecovery -n
    local raw
    local err
    device_shsh_dump $1
    err=$?
    mkdir ../saved/raws 2>/dev/null
    if [[ $1 == "dump" ]]; then
        raw="../saved/raws/rawdump_${device_ecid}-${device_type}_$(date +%Y-%m-%d-%H%M)_${shsh_onboard_iboot}.raw"
    else
        raw="../saved/raws/rawdump_${device_ecid}-${device_type}-${device_target_vers}-${device_target_build}_$(date +%Y-%m-%d-%H%M)_${shsh_onboard_iboot}.raw"
    fi
    if [[ $1 == "dump" ]] || [[ $err != 0 && -s dump.raw ]]; then
        mv dump.raw $raw
        log "Raw dump saved at: $raw"
        return
    fi
}

device_shsh_dump() {
    local shsh="../saved/shsh/${device_ecid}-${device_type}_$(date +%Y-%m-%d-%H%M).shsh"
    mkdir ../saved/shsh 2>/dev/null
    shsh="../saved/shsh/${device_ecid}-${device_type}-${device_target_vers}-${device_target_build}.shsh"
    # remove ibob for powdersn0w/dra downgraded devices. fixes unknown magic 69626f62
    local blob=$(xxd -p dump.raw | tr -d '\n')
    local bobi="626f6269"
    local blli="626c6c69"
    if [[ $blob == *"$bobi"* ]]; then
        log "Detected \"ibob\". Fixing... (This happens on DRA/powdersn0w downgraded devices)"
        rm -f dump.raw
        printf "%s" "${blob%"$bobi"*}${blli}${blob##*"$blli"}" | xxd -r -p > dump.raw
    fi
    shsh_onboard_iboot="$(cat dump.raw | strings | grep iBoot | head -1)"
    log "Raw dump iBoot version: $shsh_onboard_iboot"
    if [[ $1 == "dump" ]]; then
        return
    fi
    log "Converting raw dump to SHSH blob"
    "$dir/ticket" dump.raw dump.shsh "$ipsw_path.ipsw" -z
    if [[ $? != 0 ]]; then
        warn "Saved SHSH blobs might be invalid. Did you select the correct IPSW?"
        print "* If you selected the correct IPSW and the error is not APTicket and/or LLB, the blob is most likely usable."
    fi
    if [[ ! -s dump.shsh ]]; then
        warn "Converting onboard SHSH blobs failed."
        return 1
    fi
    mv dump.shsh $shsh
    log "Successfully saved $device_target_vers blobs: $shsh"
}

device_hacktivate() {
    local ver
    local build
    local 
    log "Get iOS version"
    check_iosvers
    cut_os_vers $device_vers
    log "Mount Filesystem"
    $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
    if (( major_ver > 9 )); then
        local message=$($ssh -p $ssh_port root@127.0.0.1 "ls /mnt2")
        if [[ $message == "" ]]; then
            warn "This version of ramdisk cannot mount /mnt2,please use “./sshrd32.sh --version=9.0.2 --bypass” and try again"
            pause
            return
        fi
    fi
    case $device_vers in
        [34]* )
            log "Creat data_ark.plist"
            echo '<plist><dict><key>com.apple.mobile.lockdown_cache-ActivationState</key><string>FactoryActivated</string></dict></plist>' > data_ark.plist
            log "Copying data_ark.plist to device"
            $scp -P $ssh_port data_ark.plist root@127.0.0.1:/mnt2/root/Library/Lockdown/data_ark.plist
            log "Rebooting"
            $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
            log "Done. Your device should reboot now"
            main_argmode="exit"
            ;;
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
            log "Rename orgin file"
            $ssh -p $ssh_port root@127.0.0.1 "mv /mnt1/usr/libexec/lockdownd /mnt1/usr/libexec/lockdownd.bak"
            log "Upload new file"
            $scp -P $ssh_port ../resources/lockdownd root@127.0.0.1:/mnt1/usr/libexec
            log "Set permissions"
            $ssh -p $ssh_port root@127.0.0.1 "chmod 755 /mnt1/usr/libexec/lockdownd"
            yesno "Do you want to rename Setup.app?"
            if [[ $? == 1 ]]; then
                $ssh -p $ssh_port root@127.0.0.1 "mv /mnt1/Applications/Setup.app /mnt1/Applications/Setup.app.bak"
            fi
            log "Rebooting"
            $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
            main_argmode="exit"
            ;;
        [78]* | 9.[012]* )
            log "Download files"
            $scp -P $ssh_port root@127.0.0.1:/mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist .
            if [[ ! -f "com.apple.MobileGestalt.plist" ]]; then
                error Download files failed
                pause
                return
            else
                log "Add key to files"
                $afc activation com.apple.MobileGestalt.plist
                if [[ ! -f "com.apple.MobileGestalt.plist.backup" ]]; then
                    error "Add key failed"
                    pause
                    return
                fi
                cp com.apple.MobileGestalt.plist.backup ../saved/$device_type
                mv ../saved/$device_type/com.apple.MobileGestalt.plist.backup ../saved/$device_type/com.apple.MobileGestalt.plist.$(date '+%Y-%m-%d-%H-%M-%S').backup

            fi
            log Replace original files
            $ssh -p $ssh_port root@127.0.0.1 "mv /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist /mnt2/mobile/Library/Caches/com.apple.MobileGestalt.plist.bak"
            log Upload files
            $scp -P $ssh_port com.apple.MobileGestalt.plist root@127.0.0.1:/mnt2/mobile/Library/Caches
            log Rename Setup.app
            $ssh -p $ssh_port root@127.0.0.1 "mv /mnt1/Applications/Setup.app /mnt1/Applications/Setup.app.bak"
            log Rebooting
            $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
            log "Done"
            main_argmode="exit"
            ;;
        9.3* | 10* )
            if [[ $platform == linux ]]; then
                warnning afc_tool is unsupport for linux,wait for commit
                return
            fi
            if [[ $major_ver == 10 ]]; then
                case $minor_ver in
                    [012] )
                    local path="/mnt2/mobile/Library/Caches"
                    ;;
                    * )
                    local path="/mnt2/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches"
                    ;;
                esac
            else
                local path="/mnt2/mobile/Library/Caches"
            fi
            log Download files
            $ssh -p $ssh_port root@127.0.0.1 "mv $path/com.apple.MobileGestalt.plist /mnt2/mobile/Media"
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
                checkmode nor
                log Please trust the device and press Enter.
                pause
                $afc download /com.apple.MobileGestalt.plist .
                if [[ ! -f "com.apple.MobileGestalt.plist" ]]; then
                    error Download failed
                    pause Press enter to exit
                    return
                else
                    log "Add key to files"
                    $afc activation com.apple.MobileGestalt.plist
                    if [[ ! -f "com.apple.MobileGestalt.plist.backup" ]]; then
                        error "Add key failed"
                        pause
                        return
                    fi
                    log Upload files
                    $afc upload com.apple.MobileGestalt.plist /
                fi
            fi
            log "Done,part1 has been completed,use ./sshrd32.sh --bypass-part-2 to start part 2"
            main_argmode="exit"
            ;;
        * )
            warn This iOS version is unsupport
            pause Press enter to enter ssh menu
            ssh_menu
            ;;
    esac
}

device_hacktivate_part2() {
    ##part2 ios9.3-ios10.3.4
    log Get ios version
    check_iosvers
    cut_os_vers $device_vers
    $ssh -p $ssh_port root@127.0.0.1 "umount /mnt1"
    $ssh -p $ssh_port root@127.0.0.1 "umount /mnt2"
    if [[ $major_ver == 10 ]]; then
        case $minor_ver in
            [012] )
            local path="/mnt2/mobile/Library/Caches"
            ;;
            * )
            local path="/mnt2/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches"
            ;;
        esac
    else
        local path="/mnt2/mobile/Library/Caches"
    fi
    log Mount Filesystem
    $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
    #log Rename Setup.app #ios10 cannot mv setup.app
    #$ssh -p $ssh_port root@127.0.0.1 "mv /mnt1/Applications/Setup.app /mnt1/Applications/Setup.app.bak"
    log Replace original files
    $ssh -p $ssh_port root@127.0.0.1 "mv $path/com.apple.MobileGestalt.plist $path/com.apple.MobileGestalt.plist.bak"
    $ssh -p $ssh_port root@127.0.0.1 "mv /mnt2/mobile/Media/com.apple.MobileGestalt.plist $path"
    log Rebooting
    $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
    log Done
    main_argmode="exit"
}


device_unblock_lock() {
    log "Mount Filesystem"
    $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
    log "Del some files"
    $ssh -p $ssh_port root@127.0.0.1 "rm -rf /mnt2/mobile/Library/Preferences/com.apple.springboard.plist"
    $ssh -p $ssh_port root@127.0.0.1 "rm -rf /mnt2/mobile/Library/SpringBoard/LockoutStateJournal.plist"
    log "Rebooting"
    $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
    main_argmode="exit"
}

device_password() {
    log "Mount Filesystem"
    $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
    log "Replace com.apple.springboard.plist"
    $ssh -p $ssh_port root@127.0.0.1 "cp /mnt2/mobile/Library/Preferences/com.apple.springboard.plist /mnt2/mobile/Library/Preferences/com.apple.springboard.plist.orig"
    $ssh -p $ssh_port root@127.0.0.1 "rm -rf /mnt2/mobile/Library/Preferences/com.apple.springboard.plist"
    $scp -P $ssh_port ../resources/password/com.apple.springboard.plist root@127.0.0.1:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist
    log "Done"
    pause
    log "Rebooting"
    $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
    main_argmode="exit"
}

device_battery() {
    local device=${device_model}ap
    local deviceid=$(echo "$device" | awk '{print toupper($0)}')
    log "Mount Filesystem"
    $ssh -p $ssh_port root@127.0.0.1 "mount.sh"
    check_iosvers
    cut_os_vers $device_vers
    if [[ $major == "9" ]] && (( minor_ver >= 3 )) || (( major_ver <= 4 )); then
        warn "Support iOS5-9.2.1 only"
        pause
        return
    elif (( major_ver >= 7 )); then
        log "Extract com.apple.springboard.plist"
        $scp -P $ssh_port root@127.0.0.1:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist .
        if [[ ! -e com.apple.springboard.plist ]]; then
            error "Unale to extract com.apple.springboard.plist"
            return
        fi
        log "Add keys"
        if [[ $platform == "macos" ]]; then
            plutil -replace SBShowBatteryLevel -bool true "com.apple.springboard.plist" 2>/dev/null || plutil -insert SBShowBatteryLevel -bool true "com.apple.springboard.plist"
        else
            $PlistBuddy -c "Set :SBShowBatteryLevel true" "com.apple.springboard.plist" 2>/dev/null || $PlistBuddy -c "Add :SBShowBatteryLevel bool true" "com.apple.springboard.plist"
        fi
        pause
        log "Replace com.apple.springboard.plist"
        $ssh -p $ssh_port root@127.0.0.1 "cp /mnt2/mobile/Library/Preferences/com.apple.springboard.plist /mnt2/mobile/Library/Preferences/com.apple.springboard.plist.orig"
        $ssh -p $ssh_port root@127.0.0.1 "rm -rf /mnt2/mobile/Library/Preferences/com.apple.springboard.plist"
        $scp -P $ssh_port com.apple.springboard.plist root@127.0.0.1:/mnt2/mobile/Library/Preferences/com.apple.springboard.plist
        log "Done"
    else
        log "Extract $deviceid.plist"
        $scp -P $ssh_port root@127.0.0.1:/mnt1/System/Library/CoreServices/SpringBoard.app/$deviceid.plist .
        if [[ ! -e $deviceid.plist ]]; then
            error "Unale to extract $deviceid.plist"
            return
        fi
        log "Add keys"
        if [[ $platform == "macos" ]]; then
            plutil -replace capabilities.gas-gauge-battery -bool true $deviceid.plist && plutil -convert xml1 $deviceid.plist
        else
            $PlistBuddy -c "Set :capabilities:gas-gauge-battery true" $deviceid.plist 2>/dev/null || $PlistBuddy -c "Add :capabilities:gas-gauge-battery bool true" $deviceid.plist
        fi
        log "Replace $deviceid.plist"
        $ssh -p $ssh_port root@127.0.0.1 "cp /mnt1/System/Library/CoreServices/SpringBoard.app/$deviceid.plist /mnt1/System/Library/CoreServices/SpringBoard.app/$deviceid.plist.orig"
        $ssh -p $ssh_port root@127.0.0.1 "rm -rf /mnt1/System/Library/CoreServices/SpringBoard.app/$deviceid.plist"
        $scp -P $ssh_port $deviceid.plist root@127.0.0.1:/mnt1/System/Library/CoreServices/SpringBoard.app/$deviceid.plist
        log "Done"
    fi
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

get_ipsw_info() {
    local ipsw_file
    if [[ $1 == "base" ]]; then
        ipsw_file="$ipsw_base_path"
    else
        if [[ $1 == "target" ]]; then
            ipsw_file="$2"
        else
            ipsw_file="$ipsw_path"
        fi
    fi    
    if [ -z "$ipsw_file" ]; then
        warn Unable to get ipsw path
        exit
    fi
    if [[ $device_proc == 1 || $device_proc == 4 ]] && [[ $ipsw_file == *1.* || $ipsw_file == *2.* ]]; then
        plist="Restore.plist"
        plist_legacy=1
    else
        plist="BuildManifest.plist"
    fi
    unzip -p "$ipsw_file" "$plist" > "$plist" 2>/dev/null
    if [ $? -ne 0 ]; then
        if [[ $device_proc == 4 ]]; then
            plist="BuildManifest.plist"
            unzip -p "$ipsw_file" "$plist" > "$plist" 2>/dev/null
            if [[ ! -f $plist ]]; then
                error "Unable extract files from this ipsw"
                return 1
            fi
        else
            error "Unable extract files from this ipsw"
            return 1
        fi
    fi
    if [[ $platform == "macos" ]]; then
        if [[ $plist == "Restore.plist" ]]; then
            device_type_ipsw_temp=$(plutil -extract "ProductType" xml1 -o - "$plist" | sed -n 's/<string>\(.*\)<\/string>/\1/p')
        else
            device_type_ipsw_temp=$(plutil -extract "SupportedProductTypes" xml1 -o - "$plist" | sed -n 's/<string>\(.*\)<\/string>/\1/p')
        fi
        device_vers=$(plutil -extract "ProductVersion" xml1 -o - "$plist" | sed -n 's/<string>\(.*\)<\/string>/\1/p')
        device_build=$(plutil -extract "ProductBuildVersion" xml1 -o - "$plist" | sed -n 's/<string>\(.*\)<\/string>/\1/p')
        device_type_ipsw=$(echo "$device_type_ipsw_temp" | tr -d '\n\r' | xargs)
    else
        if [[ $plist == "Restore.plist" ]]; then
            device_type_ipsw_temp=$(cat "$plist" | grep -i ProductType -A 1 | grep -oPm1 "(?<=<string>)[^<]+")
        else
            device_type_ipsw_temp=$(cat $plist | grep -i SupportedProductTypes -A 1 | grep -oPm1 "(?<=<string>)[^<]+")
        fi
        device_vers=$(cat $plist | grep -i ProductVersion -A 1 | grep -oPm1 "(?<=<string>)[^<]+")
        device_build=$(cat $plist | grep -i ProductBuildVersion -A 1 | grep -oPm1 "(?<=<string>)[^<]+")
        device_type_ipsw=$(echo "$device_type_ipsw_temp" | tr -d '\n\r' | xargs)
    fi
    if [[ $1 == "base" ]]; then
        device_type_ipswbase="$device_type_ipsw"
        device_base_vers="$device_vers"
        device_base_build="$device_build"
        if [[ "$device_type" != "$device_type_ipswbase" ]]; then
            ipsw_base_select_wrong=1
            ipsw_path=""
        else
            ipsw_base_select_wrong=0
        fi
    else
        device_type_ipsw="$device_type_ipsw"
        device_ipsw_vers="$device_vers"
        device_ipsw_build="$device_build"
        if [[ "$device_type" != "$device_type_ipsw" ]]; then
            ipsw_select_wrong=1
            ipsw_path=""
        else
            ipsw_select_wrong=0
        fi
    fi
    rm -f "$plist"
    return 0
}


get_firmware_info() {
    local version=
    local build=
    local mode
    firmware_version=
    firmware_buildid=
    firmware_filesize=
    firmware_sha1=
    firmware_sha256=
    firmware_md5=
    firmware_signed=
    firmware_releasedate=
    firmware_uploaddate=
    firmware_url=

    log "Get firmware info"
    validate_build $1
    if [[ $? != 1 ]]; then
        mode="build"
    else
        mode="ver"
    fi

    if [[ $device_type == "iPod1,1" || $device_type == "iPod2,1" ]]; then
        if [[ $mode == "ver" ]] && [[ $1 == 2.* || $1 == 3.* ]]; then
            if [[ ! -f $saved/invoxiplaygames.html ]]; then
                log "Downloading html"
                file_download https://invoxiplaygames.uk/ipsw/ temp.html
                if [[ -f temp.html ]]; then
                    mv temp.html $saved/invoxiplaygames.html
                else
                    error "Unable to download html"
                    exit 1
                fi
            fi
            cp $saved/invoxiplaygames.html temp.html
            local namess=$(grep -oE 'iPod[0-9],[0-9]_[^"]+\.ipsw' temp.html)
            local names=$(echo "$namess" | grep "$device_type")
            local name=$(echo "$names" | grep -E "_${1}_" | head -n 1)
            if [[ -n $name ]]; then
                firmware_url="https://invoxiplaygames.uk/ipsw/$name"
                firmware_version="$(echo "$name" | cut -d'_' -f2)"
                firmware_buildid="$(echo "$name" | cut -d'_' -f3)"
                return 0
            fi
        elif [[ $mode == "build" ]] && [[ $1 == 5* || $1 == 7* ]]; then
            if [[ ! -f $saved/invoxiplaygames.html ]]; then
                log "Downloading html"
                file_download https://invoxiplaygames.uk/ipsw/ temp.html
                if [[ -f temp.html ]]; then
                    mv temp.html $saved/invoxiplaygames.html
                else
                    error "Unable to download html"
                    exit 1
                fi
            fi
            cp $saved/invoxiplaygames.html temp.html
            local namess=$(grep -oE 'iPod[0-9],[0-9]_[^"]+\.ipsw' temp.html)
            local names=$(echo "$namess" | grep "$device_type")
            local name=$(echo "$names" | grep -E "_[^_]+_${1}_" | head -n 1)
            if [[ -n $name ]]; then
                firmware_url="https://invoxiplaygames.uk/ipsw/$name"
                firmware_version="$(echo "$name" | cut -d'_' -f2)"
                firmware_buildid="$(echo "$name" | cut -d'_' -f3)"
                return 0
            fi
        fi
    fi


    curl -s -L "https://api.ipsw.me/v4/device/$device_type?type=ipsw" -o tmp.json

    if [[ ! -f "tmp.json" ]]; then
        error Unable to get json,please check internat connection
        exit
    fi
    if [[ $mode == "ver" ]]; then
        version=$1
        if [[ "$device_type" == "iPod4,1" && "$version" == "4.1" ]]; then
            log Select version
            options=("8B117" "8B118")
            select_option "${options[@]}"
            selected_index=$?
            selected="${options[$selected_index]}"
            
            case $selected in
                "8B117" ) 
                    get_firmware_info 8B117
                    return $?
                    ;;
                "8B118" ) 
                    get_firmware_info 8B118
                    return $?
                    ;;
            esac
        fi
    elif [[ $mode == "build" ]]; then
        build=$1
    fi
    if [[ $mode == "ver" ]]; then
        firmware_version=$($jq -r ".firmwares[] | select(.version == \"$version\") | .version" "tmp.json")
        firmware_buildid=$($jq -r ".firmwares[] | select(.version == \"$version\") | .buildid" "tmp.json")
        firmware_filesize=$($jq -r ".firmwares[] | select(.version == \"$version\") | .filesize" "tmp.json")
        firmware_url=$($jq -r ".firmwares[] | select(.version == \"$version\") | .url" "tmp.json")
        firmware_sha1=$($jq -r ".firmwares[] | select(.version == \"$version\") | .sha1sum" "tmp.json")
        firmware_sha256=$($jq -r ".firmwares[] | select(.version == \"$version\") | .sha256sum" "tmp.json")
        firmware_md5=$($jq -r ".firmwares[] | select(.version == \"$version\") | .md5sum" "tmp.json")
        firmware_signed=$($jq -r ".firmwares[] | select(.version == \"$version\") | .signed" "tmp.json")
        firmware_releasedate=$($jq -r ".firmwares[] | select(.version == \"$version\") | .releasedate" "tmp.json")
        firmware_uploaddate=$($jq -r ".firmwares[] | select(.version == \"$version\") | .uploaddate" "tmp.json")
    elif [[ $mode == "build" ]]; then
        firmware_version=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .version" "tmp.json")
        firmware_buildid=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .buildid" "tmp.json")
        firmware_filesize=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .filesize" "tmp.json")
        firmware_url=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .url" "tmp.json")
        firmware_sha1=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .sha1sum" "tmp.json")
        firmware_sha256=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .sha256sum" "tmp.json")
        firmware_md5=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .md5sum" "tmp.json")
        firmware_signed=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .signed" "tmp.json")
        firmware_releasedate=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .releasedate" "tmp.json")
        firmware_uploaddate=$($jq -r ".firmwares[] | select(.buildid == \"$build\") | .uploaddate" "tmp.json")
    fi

    validate_build $firmware_buildid
    if [[ $? == 1 ]]; then
        error "Get firmware info failed"
        exit 1
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
    if [[ $1 == "no-logging" && $debug != 1 ]]; then
        "$dir/iproxy" $ssh_port $port -s 127.0.0.1 >/dev/null &
        iproxy_pid=$!
    else
        "$dir/iproxy" $ssh_port $port -s 127.0.0.1 &
        iproxy_pid=$!
    fi
    log "iproxy PID: $iproxy_pid"
    sleep 1
}


device_fw_key_check() {
    # check and download keys for device_target_build, then set the variable device_fw_key (or device_fw_key_base)
    #remove download part,replace use unzip
    local key
    local build="$device_target_build"
    if [[ $1 == "base" ]]; then
        build="$device_base_build"
    elif [[ $1 == "temp" ]]; then
        build="$2"
    fi
    device_fw_dir=../saved/$device_type/$build
    local keys_path="../saved/keys/$device_type/$build"
    if [[ ! -d $keys_path ]]; then
        mkdir -p $keys_path
    fi
    log "Checking firmware keys"
    if [[ $(cat "$keys_path/index.html" 2>/dev/null | grep -c "$build") != 1 ]]; then
        rm -f "$keys_path/index.html"
    fi
    if [[ ! -f "$keys_path/index.html" ]]; then
        cp ../resources/keys.zip .
        unzip -p keys.zip "Legacy-iOS-Kit-Keys-master/$device_type/$build/index.html" > index.html
    else
        cp $keys_path/index.html .
    fi
    if [[ $(cat index.html | grep -c "$build") != 1 ]]; then
        rm -rf index.html
        error "Wrong keys,try to download keys"
        log "Download keys"
        local try=("https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit-Keys/master/$device_type/$build/index.html"
                   "https://api.m1sta.xyz/wikiproxy/$device_type/$build")
        for i in "${try[@]}"; do
            $aria2c "$i" -o index.html
            [[ $? != 0 ]] && $curl -L "$i" -o index.html
            if [[ $(cat index.html | grep -c "$build") == 1 ]]; then
                break
            fi
        done
        if [[ -f index.html ]]; then
            cp index.html $keys_path
        else
            error "Unable to download keys,check internet connection"
            exit 1
        fi
    else
        cp index.html $keys_path
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

patch_ibec() {
    # creates file pwnediBEC to be sent to device for blob dumping
    local build_id
    if [[ ! -f ../saved/$device_type/pwnediBEC.dfu ]]; then
        case $device_type in
            iPad1,1 | iPod3,1 )
                build_id="9B206";;
            iPhone2,1 | iPhone3,[123] | iPod4,1 | iPad3,1 )
                build_id="10A403";;
            iPad2,[367] | iPad3,[25] )
                build_id="12H321";;
            iPhone5,3 )
                build_id="11B511";;
            iPhone5,4 )
                build_id="11B651";;
            * )
                build_id="10B329";;
        esac
        if [[ -n $device_rd_build ]]; then
            build_id="$device_rd_build"
        fi
        download_comp $build_id iBEC
        device_fw_key_check temp $build_id
        local name="iBEC"
        local iv=$(echo $device_fw_key_temp | $jq -j '.keys[] | select(.image == "iBEC") | .iv')
        local key=$(echo $device_fw_key_temp | $jq -j '.keys[] | select(.image == "iBEC") | .key')
        local address="0x80000000"
        if [[ $device_proc == 4 ]]; then
            address="0x40000000"
        fi
        mv iBEC $name.orig
        log "Decrypting iBEC..."
        "$dir/xpwntool" $name.orig $name.dec -iv $iv -k $key
        log "Patching iBEC..."
        if [[ $device_proc == 4 || -n $device_rd_build || $device_type == "iPad3,1" ]]; then
            "$dir/iBoot32Patcher" $name.dec $name.patched --rsa --ticket -b "rd=md0 -v amfi=0xff cs_enforcement_disable=1" -c "go" $address
        else
            $bspatch $name.dec $name.patched "../resources/patch/$download_targetfile.patch"
        fi
        "$dir/xpwntool" $name.patched pwnediBEC.dfu -t $name.orig
        rm $name.dec $name.orig $name.patched
        cp pwnediBEC.dfu ../saved/$device_type/
        log "Pwned iBEC img3 saved at: saved/$device_type/pwnediBEC.dfu"
    else
        log Found exist Pwned iBEC
        cp ../saved/$device_type/pwnediBEC.dfu .
    fi
}


download_comp() {
    # usage: download_comp [build_id] [comp]
    local build_id="$1"
    local comp="$2"
    get_firmware_info $build_id
    local ipsw_url=$firmware_url
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
        #github may be banned,remove this way
        #$aria2c "https://raw.githubusercontent.com/littlebyteorg/appledb/refs/heads/gh-pages/ios/i${phone};$build_id.json" -o tmp.json
        #[[ $? != 0 ]] && $curl -L "https://raw.githubusercontent.com/littlebyteorg/appledb/refs/heads/gh-pages/ios/i${phone};$build_id.json" -o tmp.json
        #url="$(cat tmp.json | $jq -r ".sources[] | select(.type == \"ipsw\" and any(.deviceMap[]; . == \"$device_type\")) | .links[0].url")"
        if [[ -z $url ]]; then
            get_firmware_info $build_id
        fi
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

file_download() {
    # usage: file_download {link} {target location} {sha1}
    local filename="$(basename $2)"
    log "Downloading $filename..."
    $aria2c "$1" -o $2
    [[ $? != 0 ]] && $curl -L "$1" -o $2
    if [[ ! -s $2 ]]; then
        error "Downloading $2 failed. Please run the script again"
    fi
    if [[ -z $3 ]]; then
        return
    fi
    local sha1=$($sha1sum $2 | awk '{print $1}')
    if [[ $sha1 != "$3" ]]; then
        error "Verifying $filename failed. The downloaded file may be corrupted or incomplete. Please run the script again" \
        "* SHA1sum mismatch. Expected $3, got $sha1"
    fi
}

####others#####

clean() {
    exit_message
    kill $httpserver_pid $iproxy_pid $anisette_pid $sshfs_pid 2>/dev/null
    popd &>/dev/null
    rm -rf "$(dirname "$0")/tmp$$/"* "$(dirname "$0")/iP"*/ "$(dirname "$0")/tmp$$/" 2>/dev/null
    rm -rf $(dirname "$0")/tmp*
    if [[ $platform == "macos" && $(ls "$(dirname "$0")" | grep -v tmp$$ | grep -c tmp) == 0 &&
          $no_finder != 1 ]]; then
        killall -CONT AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater
    fi
}

exit_message() {
    print "* Save the terminal output now if needed. (macOS: Cmd+S, Linux: Ctrl+Shift+S)"
    print "*Platform:$platform_message*"
    pause "Press Enter to exit"
}
 
display_help() {
    readme="../README.md"
    if [[ ! -f $readme ]]; then
        error "Unable to find Readme file,please use ./sshrd32.sh --update to update this script"
        return
    else
        clear
    fi
    print  "*** SSHRD_Script_32Bit ***"
    print  "- $platform_message -"
    print  "- Script by MrY0000 -"
    print  "- Thanks LuckZGD Setup.app -"
    print  "- Forked from Legacy-iOS-Kit(https://github.com/LukeZGD/Legacy-iOS-Kit) -"
    print "Usage:"
    sed -n '/^## Usage/,/^## Main Args/p' "$readme" | sed '$d' | tail -n +2
    print "Main Args:"
    sed -n '/^## Main Args/,/^## Other Args/p' "$readme" | sed '$d' | tail -n +2
    print "Other Args:"
    awk '/^## Other Args/{flag=1; next} /^## [A-Z]/{flag=0} flag' "$readme" | sed 's/^- .\/sshrd32.sh/-/'
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
    local msg="Do you want to continue?"
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

main() {
    local try
    local mode
    local mode1
    oscheck
    set_ssh_config
    set_path
    for i in "$@"; do
        case "$i" in
            [0-9]*.[0-9]* | [0-9]*[A-Za-z][0-9]* ) device_rd_ver="$i";;
            reboot ) mode="reboot";;
            ssh ) mode="ssh";;
            menu ) mode="menu";;
            get-ios-ver ) mode="get_ios_ver";;
            dump-blobs | dump-raws )
                if [[ $i == "dump-blobs" ]]; then
                    mode="blobs"
                else
                    mode="raws"
                fi
                ;;
            jailbreak ) mode="jailbreak";;
            password ) mode="password";;
            bruteforce ) mode="bruteforce";;
            hacktivate ) mode="hacktivate";;
            hacktivate-part-2 ) mode="hacktivate_part2";;
            update ) mode="update";;
            help ) mode="help";;
            #other options
            --irec ) mode1="irec";;
            --no-device )
                device_argmode=none
                ;;
            --debug ) mode1="debug";;
            --device=* ) device_type="${i#--device=}";;
            --ipsw ) mode1="ipsw";;
            * ) warn "Unknown command,use"./sshrd32.sh help" to use right command"; exit;;
        esac
    done
    main_argmode=$mode
    other_argmode=$mode1
    #without device check
    case $mode in
        "reboot" | "ssh" | "menu" ) device_argmode=none;;
    esac

    if [[ -n $device_type ]]; then
        device_argmode=none
    elif [[ $mode == "help" ]]; then
        display_help
        exit
    fi

    if [[ $device_argmode == "none" ]] && [[ -z $device_type ]]; then
        if [[ $mode == "menu" ]]; then
            log "Enter your device type"
            read device_type
            device_info
        fi
    elif [[ $device_argmode != "none" ]]; then
        if [[ $mode1 == "irec" ]]; then
            checkmode DFUall irec
        elif [[ $platform == linux ]]; then
            checkmode DFUall irec
        else
            checkmode DFUall
        fi
    fi
    
    case $mode in
        "ssh" | "reboot" | "menu" )
            device_iproxy
            if [[ $mode == "ssh" ]]; then
                ssh_message
                $ssh -p $ssh_port root@127.0.0.1
            elif [[ $mode == "reboot" ]]; then
                log "Rebooting"
                $ssh -p $ssh_port root@127.0.0.1 "reboot_bak"
                main_argmode="exit"
            elif [[ $mode == "menu" ]]; then
                ssh_menu
            fi
            if [[ $main_argmode == "exit" ]]; then
                exit
            else
                lastest_enter
            fi
        ;;
        "blobs" | "raws" )
            log "Select iPSW(Please select right ipsw,if you don't know ios version,use ./sshrd32.sh get-ios-ver)"
            local ipsw_try123=0
            while true; do
                local ipsw_path1="$($zenity --file-selection --mulprintle --file-filter='IPSW | *.ipsw' --title="Select IPSW file(s)")"
                ((ipsw_try123++))
                if [[ -n "$ipsw_path1" ]]; then
                    break
                fi
                if [[ $ipsw_try123 == 10 ]]; then
                    error "Unable to select ipsw, please run the script again"
                    exit 1
                fi
            done
            get_ipsw_info target $ipsw_path1
            ipsw_path="${ipsw_path1%.ipsw}"
            device_info
            device_pwn
            if [[ $i == "dump-raws" ]]; then
                device_raw_dump dump
            else
                device_raw_dump
            fi
            exit
        ;;
        "hackvate_part2" ) device_rd_ver="9.0.2";;
    esac

    device_info
    ramdisk


}

for i in "$@"; do
    case "$i" in
        --debug )
            debug_mode=1
            menu_old=1
            set -x
        ;;
    esac
done


main $@

popd >/dev/null