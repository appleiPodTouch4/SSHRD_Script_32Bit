@echo off
chcp 936 >nul
title SSHRD-Script-32Bit-Windows
setlocal enabledelayedexpansion

set "script_dir=%~dp0"

for /d %%i in ("%~dp0tmp*") do rd /s /q "%%i" 2>nul

for /f "tokens=2 delims==" %%i in ('wmic process where "Name='cmd.exe' and CommandLine like '%%%-0%%'" get ParentProcessId /value 2^>nul') do (
    for /f "delims=" %%j in ("%%i") do set "PID=%%j"
)
set "PID=%PID: =%"

md "%script_dir%tmp%PID%" 2>nul
pushd "%script_dir%tmp%PID%" 2>nul

set "dir=..\bin\windows"
set "saved=..\saved"
set "resources=..\resources"
set "ssh_port=2222"
set "sshpass=%dir%\sshpass.exe"
set "irecovery=%dir%\irecovery.exe"
set "irecoverys=%dir%\irecoverys.exe"
set "iBoot32Patcher=%dir%\iBoot32Patcher.exe"
set "hfsplus=%dir%\hfsplus.exe"
set "jq=%dir%\jq.exe"
set "xpwntool=%dir%\xpwntool.exe"
set "iproxy=%dir%\iproxy.exe"
set "bspatch=%dir%\bspatch.exe"
set "curl=%dir%\curl.exe"
set "grep=%dir%\grep.exe"
set "plutil=%dir%\plutil.exe"
set "sed=%dir%\sed.exe"
set "gawk=%dir%\gawk.exe"
set "ideviceinfo=%dir%\ideviceinfo.exe"
set "cut=%dir%\cut.exe"
set "idevicerestore=%dir%\idevicerestore.exe"
set "zip=%dir%\7z.exe"
set "pzb=%dir%\pzb\pzb.exe"
set "ssh1=%dir%\OpenSSH\ssh.exe"
set "sftp1=%dir%\OpenSSH\sftp.exe"
set "scp1=%dir%\OpenSSH\scp.exe"
set "cat=%dir%\cat.exe"
set "python=%dir%\Python2.7\python.exe"
set "ipwndfu=%dir%\ipwndfu\ipwndfu"
set "primepwn=%dir%\primepwn\primepwn.exe"
set "zadig=%dir%\zadig.exe"
set "shasum256=%dir%\shasum256.exe"
set "sha1sum=%dir%\sha1sum.exe"
set "device_rd_build_custom=%~1"
set version=""
set build=""

for /f "tokens=4-5 delims=. " %%a in ('ver') do (
    if "%%a"=="Version" ( set "winver=%%b" ) else ( set "winver=%%a" )
)

if !winver! LSS 6 (
    echo.
    echo Only support Windows7 +
    exit /b 0
)


goto main %~1


:main
    call :set_ssh_config
    if "%~1"=="ssh" (
        call :ssh_message
        exit /b
    ) else if "%~1"=="menu" (
        call :device_iproxy
        call :ssh_check
        call :menu
        exit /b
    )
    call :checkmode "DFU"
    call :device_info
    echo %device_model%
    call :ramdisk %~1 
    call :clean
    exit /b


:log
    echo [Log] %*
    exit /b

:error
    echo [ERROR] %*
    exit /b

:warn
    echo [WARNING] %*
    exit /b

:print
    echo [*] %*
    exit /b

:clean
    popd 2>nul
    for /d %%i in ("%script_dir%tmp*") do (
        rd /s /q "%%i" 2>nul
    )
    exit /b

:unzip
    set "archive=%~1"
    set "file=%~2"
    set "dest=%~3"

    if not defined dest set "dest=."

    "%zip%" e "%archive%" "%file%" -o"%dest%" -y >nul 2>&1

    exit /b 0

:pzb
    set "remote_url=%~1"
    set "file_in_zip=%~2"
    set "target_dir=%~3"
    set "target_name=%~4"
    set "remote_url=%remote_url:https://=http://%"
    set "file_in_zip=%file_in_zip:\=/%"
    call :log Downloading %file_in_zip% from "%remote_url%"
    ::if not exist "%target_dir%" mkdir "%target_dir%"
    ::(
    ::    echo %file_in_zip%
    ::    echo %target_dir%\%target_name%
    ::) | "%pzb%" "%remote_url%" >nul
    %pzb% -g %file_in_zip% -o %target_dir%\%target_name% %remote_url%
    if exist "%target_dir%\%target_name%" (
        call :log File saved at: %target_dir%\%target_name%
        exit /b 0
    ) else (
        call :error Unable to download files
        exit /b 0
    )

:zenity
    set "selected_file="
    set "ps_cmd=[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; $g = New-Object System.Windows.Forms.OpenFileDialog; $g.Multiselect = $true; $g.Title = '%~2'; $g.Filter = '%~1'; $g.InitialDirectory = '%cd%'; if($g.ShowDialog() -eq 'OK'){ $g.FileNames }"
    for /f "delims=" %%I in ('powershell -NoProfile -Command "%ps_cmd%"') do set "selected_file=%%I"
    if defined selected_file (exit /b 0) else (exit /b 1)

:set_ssh_config
    set "ssh_cmd=%ssh1%"
    set "scp_cmd=%scp1%"

    if "%~1"=="" (
        copy "..\resources\ssh_config" ".\ssh_config" >nul
        
        %ssh_cmd% -V 2> "%temp%\ssh_ver.txt"
        
        set "found=0"
        findstr /r /c:"SSH_8\.[89]" /c:"SSH_9\." /c:"SSH_1" "%temp%\ssh_ver.txt" >nul
        if %errorlevel% equ 0 (
            echo     PubkeyAcceptedAlgorithms +ssh-rsa>> ".\ssh_config"
            set "found=1"
        )
        
        if "%found%"=="0" (
            findstr /c:"SSH_6" "%temp%\ssh_ver.txt" >nul
            if %errorlevel% equ 0 (
                type "..\resources\ssh_config" | sed "s/Add/#Add/g" | sed "s/HostKeyA/#HostKeyA/g" > ".\ssh_config"
            )
        )
        del "%temp%\ssh_ver.txt"
        
        set "ssh=%sshpass% -p alpine %ssh_cmd% -F .\ssh_config"
        set "scp=%sshpass% -p alpine %scp_cmd% -F .\ssh_config"
    )
    
    if "%~1"=="pass" (
        set "ssh=%sshpass% -p %~2 %ssh_cmd% -F .\ssh_config"
        set "scp=%sshpass% -p %~2 %scp_cmd% -F .\ssh_config"
    )
    exit /b 0

:checkmode
    set "mode="
    set "wait_timeout=%~2"
    if not defined wait_timeout set "wait_timeout=0"
    set /a wait_secs=0
    if /i "%~1"=="nor" (
        call :log Waiting for the device to enter Normal mode
        :loop_nor
        set "device_ver="
        for /f "delims=" %%i in ('cmd /c ""%ideviceinfo%" -s 2^>nul | "%grep%" "ProductVersion:" | "%cut%" -d" " -f2"') do (
            set "device_ver=%%i"
        )
        if defined device_ver (
            echo !device_ver!| findstr /r "^[0-9][0-9]*\.[0-9][0-9]*" >nul
            if !errorlevel! EQU 0 exit /b
        )
        timeout /t 1 /nobreak >nul
        goto loop_nor
    )

    if /i "%~1"=="rec" set "mode=Recovery"
    if /i "%~1"=="DFU" set "mode=DFU"
    if /i "%~1"=="DFUall" set "mode=DFU"

    if defined mode (
        call :log Waiting for the device to enter !mode! mode
        :loop_mode
            set "device_mode="
            for /f "delims=" %%i in ('cmd /c ""%irecovery%" -q 2^>nul | "%grep%" -w "MODE" | "%cut%" -c 7-"') do (
                set "device_mode=%%i"
            )

            if defined device_mode (
                
                echo !device_mode! | findstr /i "WTF" >nul
                if !errorlevel! EQU 0 (
                    call :device_s5l8900xall
                    exit /b
                )
                echo !device_mode! | findstr /i "!mode!" >nul
                if !errorlevel! EQU 0 exit /b
            )
            
            if !wait_timeout! GTR 0 (
                set /a wait_secs+=1
                if !wait_secs! GEQ !wait_timeout! (
                    call :error Timed out waiting for !mode! mode.
                    exit /b 1
                )
            )
            :: ????????????? 1 ???
            timeout /t 1 /nobreak >nul
            goto loop_mode
    )
    exit /b

:device_info
    if not defined device_type (
        for /f "delims=" %%i in ('cmd /c "%irecovery% -q 2^>nul | "%grep%" -i "product" | "%gawk%" -F": " "{print $2}""') do (
            set "device_type=%%i"
        )
    ) else (
        echo !device_type!| findstr /r "^iPhone[1-9][0-9]*,[0-9]*$ ^iPad[1-9][0-9]*,[0-9]*$ ^iPod[1-9][0-9]*,[0-9]*$" >nul
        if !errorlevel! NEQ 0 (
            :loop_input
            echo Device type entered incorrectly, please re-enter.
            set /p device_type=
            echo !device_type!| findstr /r "^iPhone[1-9][0-9]*,[0-9]*$ ^iPad[1-9][0-9]*,[0-9]*$ ^iPod[1-9][0-9]*,[0-9]*$" >nul
            if !errorlevel! NEQ 0 goto loop_input
        )
    )

    if not exist "%saved%\!device_type!" (
        md "%saved%\!device_type!" 2>nul
    )

    set "device_proc="
    echo !device_type!| findstr /r "^iPhone1, ^iPod1,1" >nul
    if !errorlevel! EQU 0 set device_proc=1

    echo !device_type!| findstr /r "^iPad1,1 ^iPhone[23], ^iPod[234],1" >nul
    if !errorlevel! EQU 0 set device_proc=4

    echo !device_type!| findstr /r "^iPad2, ^iPad3,[123] ^iPhone4,1 ^iPod5,1" >nul
    if !errorlevel! EQU 0 set device_proc=5

    echo !device_type!| findstr /r "^iPad3, ^iPhone5," >nul
    if !errorlevel! EQU 0 (
        set device_proc=6
        set device_argmode=none
    )
    set "device_model="
    if "!device_type!"=="iPad1,1" set "device_model=k48"
    if "!device_type!"=="iPad2,1" set "device_model=k93"
    if "!device_type!"=="iPad2,2" set "device_model=k94"
    if "!device_type!"=="iPad2,3" set "device_model=k95"
    if "!device_type!"=="iPad2,4" set "device_model=k93a"
    if "!device_type!"=="iPad2,5" set "device_model=p105"
    if "!device_type!"=="iPad2,6" set "device_model=p106"
    if "!device_type!"=="iPad2,7" set "device_model=p107"
    if "!device_type!"=="iPad3,1" set "device_model=j1"
    if "!device_type!"=="iPad3,2" set "device_model=j2"
    if "!device_type!"=="iPad3,3" set "device_model=j2a"
    if "!device_type!"=="iPad3,4" set "device_model=p101"
    if "!device_type!"=="iPad3,5" set "device_model=p102"
    if "!device_type!"=="iPad3,6" set "device_model=p103"
    if "!device_type!"=="iPhone1,1" set "device_model=m68"
    if "!device_type!"=="iPhone1,2" set "device_model=n82"
    if "!device_type!"=="iPhone2,1" set "device_model=n88"
    if "!device_type!"=="iPhone3,1" set "device_model=n90"
    if "!device_type!"=="iPhone3,2" set "device_model=n90b"
    if "!device_type!"=="iPhone3,3" set "device_model=n92"
    if "!device_type!"=="iPhone4,1" set "device_model=n94"
    if "!device_type!"=="iPhone5,1" set "device_model=n41"
    if "!device_type!"=="iPhone5,2" set "device_model=n42"
    if "!device_type!"=="iPhone5,3" set "device_model=n48"
    if "!device_type!"=="iPhone5,4" set "device_model=n49"
    if "!device_type!"=="iPod1,1" set "device_model=n45"
    if "!device_type!"=="iPod2,1" set "device_model=n72"
    if "!device_type!"=="iPod3,1" set "device_model=n18"
    if "!device_type!"=="iPod4,1" set "device_model=n81"
    if "!device_type!"=="iPod5,1" set "device_model=n78"

    if not defined device_model (
        call :error Unsupport for 64Bit device
        exit /b 1
    )

    exit /b 0   

:cut_os_vers
    set "target=%~1"
    set "val=%~1"
    if "%~1"=="device" (
        set "val=%~2"
        set "target=device"
    )

    for /f %%a in ('echo %val%^| "%cut%" -c 1') do set "device_det=%%a"
    for /f %%a in ('echo %val%^| "%cut%" -c -2') do set "device_det2=%%a"
    for /f %%a in ('echo %val%^| "%cut%" -c 3') do set "device_det3=%%a"
    for /f %%a in ('echo %val%^| "%cut%" -c 4') do set "device_det4=%%a"
    for /f %%a in ('echo %val%^| "%cut%" -c 4-5') do set "device_det5=%%a"
    for /f %%a in ('echo %val%^| "%cut%" -c 5-6') do set "device_det6=%%a"

    if "%target%"=="device" (
        if "%device_det%"=="1" (
            set "device_major_ver=%device_det2%"
            set "device_minor_ver=%device_det4%"
            set "device_nano_ver=%device_det6%"
            for /f %%a in ('echo %device_nano_ver%^| "%cut%" -c 2') do set "device_nano_ver_wtd=%%a"
        ) else (
            set "device_major_ver=%device_det%"
            set "device_minor_ver=%device_det3%"
            set "device_nano_ver=%device_det5%"
            for /f %%a in ('echo %device_nano_ver%^| "%cut%" -c 2') do set "device_nano_ver_wtd=%%a"
        )
    ) else (
        if "%device_det%"=="1" (
            set "major_ver=%device_det2%"
            set "minor_ver=%device_det4%"
            set "nano_ver=%device_det6%"
            for /f %%a in ('echo %nano_ver%^| "%cut%" -c 2') do set "nano_ver_wtd=%%a"
        ) else (
            set "major_ver=%device_det%"
            set "minor_ver=%device_det3%"
            set "nano_ver=%device_det5%"
            for /f %%a in ('echo %nano_ver%^| "%cut%" -c 2') do set "nano_ver_wtd=%%a"
        )
    )
    exit /b 0

:device_iproxy
    set "port=22"
    if not "%~2"=="" set "port=%~2"
    TASKKILL /F /IM iproxy.exe >nul 2>&1
    call :log Running iproxy for SSH...

    if "%~1"=="no-logging" (
        if not "%debug_mode%"=="1" (
            start /b %dir%\iproxy.exe %ssh_port% %port% >nul 2>&1
        ) else (
            start /b %dir%\iproxy.exe %ssh_port% %port%
        )
    ) else (
        start /b %dir%\iproxy.exe %ssh_port% %port%
    )

    set "iproxy_pid="
    for /f "tokens=2" %%a in ('tasklist /nh /fi "imagename eq iproxy.exe"') do set "iproxy_pid=%%a"
    
    call :log "iproxy PID: %iproxy_pid%"
    timeout /t 1 /nobreak >nul
    exit /b 0


:device_fw_key_check
    set "build=!device_target_build!"
    if "%~1"=="base" set "build=%device_base_build%"
    if "%~1"=="temp" set "build=%~2"
    
    set "device_fw_dir=..\saved\%device_type%\%build%"
    set "keys_path=."
    call :log Checking firmware keys
    
    set "match_found=0"
    if exist "%keys_path%\index.html" (
        type "%keys_path%\index.html" | "%grep%" -q "%build%"
        if %errorlevel% equ 0 set "match_found=1"
    )
    
    if "%match_found%"=="0" (
        if exist "%keys_path%\index.html" del "%keys_path%\index.html"
    )
    
    if not exist "%keys_path%\index.html" (
        copy "..\resources\keys.zip" ".\keys.zip" >nul
        call :unzip ".\keys.zip" "Legacy-iOS-Kit-Keys-master/%device_type%/!build!/index.html" "."
    )

    if "%~1"=="base" (
        for /f "usebackq tokens=*" %%a in (`type index.html`) do set "device_fw_key_base=%%a"
    ) else if "%~1"=="temp" (
        for /f "usebackq tokens=*" %%a in (`type index.html`) do set "device_fw_key_temp=%%a"
    ) else (
        for /f "usebackq tokens=*" %%a in (`type index.html`) do set "device_fw_key=%%a"
    )
    exit /b 0

:get_firmware_info_invo
    set url=""
    if "%device_type%"=="iPod1,1" (
        call :cut_os_vers !version!
        if "!major_ver!" LEQ "3" (
            for /f "delims=" %%i in ('%grep% "%device_type%"_"!version!" ..\resources\ipsw.txt') do set "url=%%i"
        )
    ) else if "%device_type%"=="iPod2,1" (
        call :cut_os_vers !version!
        if "!major_ver!" LEQ "3" (
            for /f "delims=" %%i in ('%grep% "%device_type%"_"!version!" ..\resources\ipsw.txt') do set "url=%%i"
        )
    )
    exit /b


:get_firmware_info
    set "build_id=" & set "filesize=" & set "url=" & set "sha1=" & set "sha256=" & set "md5="
    set "signed=" & set "releasedate=" & set "uploaddate=" & set "version=" & set "build="
    set version=""
    set build=""
    set "mode=%~1"

    if /i "%mode%"=="ver" (
        set "version=%~2"
        if "%device_type%"=="iPod4,1" (
            if "!version!"=="4.1" (
                call :select_option "build4.1" "8B117" "8B118"
                if "!build4.1!"=="0" (
                    call :get_firmware_info build 8B117
                    exit /b
                ) else (
                    call :get_firmware_info build 8B118
                    exit /b
                )
            )
        )
    )

    if /i "%mode%"=="build" (
        set "build=%~2"
    )

    %curl% -s -L "https://api.ipsw.me/v4/device/%device_type%?type=ipsw" -o "tmp.json"

    if /i "%mode%"=="ver" (
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .buildid" "tmp.json"') do set "build_id=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .filesize" "tmp.json"') do set "filesize=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .url" "tmp.json"') do set "url=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .sha1sum" "tmp.json"') do set "sha1=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .sha256sum" "tmp.json"') do set "sha256=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .md5sum" "tmp.json"') do set "md5=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .signed" "tmp.json"') do set "signed=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .releasedate" "tmp.json"') do set "releasedate=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.version == \"%version%\") | .uploaddate" "tmp.json"') do set "uploaddate=%%i"
        exit /b
    )

    if /i "%mode%"=="build" (
        set "build_id=%build%"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .filesize" "tmp.json"') do set "filesize=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .url" "tmp.json"') do set "url=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .sha1sum" "tmp.json"') do set "sha1=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .sha256sum" "tmp.json"') do set "sha256=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .md5sum" "tmp.json"') do set "md5=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .signed" "tmp.json"') do set "signed=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .releasedate" "tmp.json"') do set "releasedate=%%i"
        for /f "delims=" %%i in ('%jq% -r ".firmwares[] | select(.buildid == \"%build%\") | .uploaddate" "tmp.json"') do set "uploaddate=%%i"
        exit /b
    )

:get_ipsw_info
    call :zenity "IPSW | *.ipsw" "Select IPSW file(s)"
    if %errorlevel% neq 0 exit /b 1
    set "ipsw_path=%selected_file%"
    call :unzip "%ipsw_path%" "BuildManifest.plist" "."
    
    "%plutil%" -convert xml1 -o "BuildManifest_Text.plist" "BuildManifest.plist" >nul 2>&1
    
    "%grep%" -i "SupportedProductTypes" -A 5 "BuildManifest_Text.plist" | "%sed%" -n "s/.*<string>\(.*\)<\/string>.*/\1/p" > "%temp%\type_raw.log"
    "%grep%" -i "ProductVersion" -A 1 "BuildManifest_Text.plist" | "%sed%" -n "2s/.*<string>\(.*\)<\/string>.*/\1/p" > "%temp%\ver_final.log"
    "%grep%" -i "ProductBuildVersion" -A 1 "BuildManifest_Text.plist" | "%sed%" -n "2s/.*<string>\(.*\)<\/string>.*/\1/p" > "%temp%\build_final.log"
    
    set "device_type_ipsw="
    for /f "usebackq tokens=* delims=" %%i in ("%temp%\type_raw.log") do (
        if defined device_type_ipsw (set "device_type_ipsw=%device_type_ipsw% %%i") else (set "device_type_ipsw=%%i")
    )
    for /f "usebackq tokens=* delims=" %%i in ("%temp%\ver_final.log") do set "device_vers=%%i"
    for /f "usebackq tokens=* delims=" %%i in ("%temp%\build_final.log") do set "device_build=%%i"
    
    del "BuildManifest_Text.plist" "%temp%\type_raw.log" "%temp%\ver_final.log" "%temp%\build_final.log"
    
    exit /b 0

:device_pwn
    setlocal enabledelayedexpansion
    powershell -Command "Get-PnpDevice -Present:$false | Where-Object { $_.FriendlyName -like '*Apple Mobile Device*' } | ForEach-Object { pnputil /remove-device $_.InstanceId }" >nul 2>&1
    for /f "delims=" %%x in ('%irecovery% -q 2^>nul ^| %grep% "CPID:" ^| %gawk% -F"0x" "{print $2}"') do set CPID=%%x
    call :log Getting device info and pwning... this may take a second
    if %device_proc%==5 (
        call :warn pwn a5 device needs Arduino+USB Host Shield or Pi Pico
        call :log when you have been pwned,press enter to continue
        pause
        for /f "delims=" %%x in ('%irecovery% -q 2^>nul ^| %grep% "PWND:" ^| %gawk% -F" " "{print $2}"') do set "PWND=%%x"
        if "!PWND!"=="" (
            call :warn Pwn your device first
            pause
            exit /b 1
        )
        %primepwn% %resources%\Firmwaredfu\ibss\%device_type%
        if %ERRORLEVEL% equ 0 (
            call :log Device has been pwned
        ) else (
            call :error Unable to pwn device
        )
    ) else if %device_proc%==1 (
        exit /b
    ) else (
        %primepwn%
        for /f "delims=" %%x in ('%irecovery% -q 2^>nul ^| %grep% "PWND:" ^| %gawk% -F" " "{print $2}"') do set "PWND=%%x"
        if "!PWND!"=="" (
            call :error Unable to pwn device
            pause
            exit /b 1
        ) else (
            call :log Device has been pwned
        )
    )

	timeout /T 3 /NOBREAK >nul
    exit /b 0

:device_s5l8900xall
    set "wtf_sha=cb96954185a91712c47f20adb519db45a318c30f"
    set "wtf_saved=..\saved\patches\WTF.s5l8900xall.RELEASE.dfu"
    set "wtf_patched=!wtf_saved!.patched"
    set "wtf_patch=..\resources\patch\WTF.s5l8900xall.RELEASE.patch"
    
    if not exist "..\saved" mkdir "..\saved"
    if not exist "..\saved\patches" mkdir "..\saved\patches"

    set "wtf_sha_local="
    if exist "!wtf_saved!" (
        for /f "delims=" %%a in ('""%sha1sum%" "!wtf_saved!" 2^>nul | "%gawk%" "{print $1}""') do set "wtf_sha_local=%%a"
    )
    
    if not "!wtf_sha_local!"=="!wtf_sha!" (
        call :log "Downloading WTF.s5l8900xall..."
        ::call :pzb "http://appldnld.apple.com/iPhone/061-7481.20100202.4orot/iPhone1,1_3.1.3_7E18_Restore.ipsw" "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu" "." WTF.s5l8900xall.RELEASE.dfu
        %pzb% -g "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu" -o "WTF.s5l8900xall.RELEASE.dfu" "http://appldnld.apple.com/iPhone/061-7481.20100202.4orot/iPhone1,1_3.1.3_7E18_Restore.ipsw"
        if exist "!wtf_saved!" del /f /q "!wtf_saved!"
        move /y "WTF.s5l8900xall.RELEASE.dfu" "!wtf_saved!" >nul
    )
    
    set "wtf_sha_local="
    for /f "delims=" %%a in ('""%sha1sum%" "!wtf_saved!" | "%gawk%" "{print $1}""') do set "wtf_sha_local=%%a"
    if "!wtf_sha_local:~0,1!"=="\" set "wtf_sha_local=!wtf_sha_local:~1!"

    if not "!wtf_sha_local!"=="!wtf_sha!" (
        call :error SHA1sum mismatch. Expected !wtf_sha!, got !wtf_sha_local!. Please run the script again
        exit /b 1
    )
    
    if exist "!wtf_patched!" del /f /q "!wtf_patched!"
    
    call :log Patching WTF.s5l8900xall...
    "%dir%\bspatch" "!wtf_saved!" "!wtf_patched!" "!wtf_patch!"
    
    call :log Sending patched WTF.s5l8900xall (Pwnage 2.0)...
    "%irecovery%" -f "!wtf_patched!"
    
    call :checkmode DFU
    timeout /t 1 /nobreak >nul
    
    set "device_srtg="
    for /f "tokens=2 delims=: " %%a in ('""%irecovery%" -q | "%grep%" "SRTG""') do set "device_srtg=%%a"
    
    call :log SRTG: !device_srtg!
    
    if "!device_srtg!"=="iBoot-636.66.3x" (
        set "device_argmode="
        
        for /f "tokens=2 delims=: " %%a in ('""%irecovery%" -q | "%grep%" "PRODUCT""') do set "device_type=%%a"
        
        set "raw_model="
        for /f "tokens=2 delims=: " %%a in ('""%irecovery%" -q | "%grep%" "MODEL""') do set "raw_model=%%a"
        if defined raw_model (
            set "device_model=!raw_model:~0,-2!"
        )
        
        set "device_pwnd=Pwnage 2.0"
    )
    exit /b 0

:download_comp
    set "build_id=%~1"
    set "comp=%~2"

    set "download_targetfile=!comp!.!device_model!"
    if not "!build_id:~0,2!"=="12" set "download_targetfile=!download_targetfile!ap"
    set "download_targetfile=!download_targetfile!.RELEASE"

    if exist "..\saved\!device_type!\!comp!_!build_id!.dfu" (
        copy /y "..\saved\!device_type!\!comp!_!build_id!.dfu" "!comp!" >nul
    ) else (
        call :log "Downloading !comp!..."
        "%pzb%" -g "Firmware/dfu/!download_targetfile!.dfu" -o "!comp!" "%url%"
        copy /y "!comp!" "..\saved\!device_type!\!comp!_!build_id!.dfu" >nul
    )
    exit /b 0

:patch_ibss
    call :download_comp !build_id! iBSS
    call :device_fw_key_check temp !build_id!

    for /f "delims=" %%I in ('echo !device_fw_key_temp! ^| "%jq%" -j --arg img "iBSS" ".keys[] | select(.image == $img) | .iv"') do set "iv=%%I"
    for /f "delims=" %%K in ('echo !device_fw_key_temp! ^| "%jq%" -j --arg img "iBSS" ".keys[] | select(.image == $img) | .key"') do set "key=%%K"

    call :log "Decrypting iBSS..."
    "%xpwntool%" iBSS iBSS.dec -iv !iv! -k !key!

    call :log "Patching iBSS..."
    "%iBoot32Patcher%" iBSS.dec pwnediBSS_!build_id! --rsa
    "%xpwntool%" pwnediBSS_!build_id! pwnediBSS_!build_id!.dfu -t iBSS

    copy /y pwnediBSS_!build_id! "..\saved\!device_type!\" >nul
    copy /y pwnediBSS.dfu_!build_id! "..\saved\!device_type!\" >nul

    call :log "Pwned iBSS saved at: saved/!device_type!/pwnediBSS_!build_id!"
    call :log "Pwned iBSS img3 saved at: saved/!device_type!/pwnediBSS_!build_id!.dfu"
    exit /b


:ramdisk
    setlocal enabledelayedexpansion
    set "rec=2"
    set "all_flash=Firmware/all_flash/all_flash.!device_model!ap.production"

    if "%~1"=="setnvram" (
        set "rec=%~2"
    )

    set "comps=iBSS iBEC DeviceTree Kernelcache"
    set "comps=!comps! RestoreRamdisk"

    set "device_target_build=10B329"
    set "device_target_vers=6.1.3" 
    echo !device_type!| findstr /r "^iPhone1,[12] ^iPod1,1" >nul
    if !errorlevel! EQU 0 (
        set "device_target_build=7E18"
        set "device_target_vers=3.1.3"
    )
    if "!device_type!"=="iPod2,1" (
        set "device_target_build=8C148"
        set "device_target_vers=4.2.1"
    )
    if "!device_type!"=="iPod3,1" (
        set "device_target_build=9B206"
        set "device_target_vers=5.1.1"
    )
    if "!device_type!"=="iPad1,1" (
        set "device_target_build=9B206"
        set "device_target_vers=5.1.1"
    )
    
    echo !device_type!| findstr /r "^iPhone2,1 ^iPod4,1" >nul
    if !errorlevel! EQU 0 (
        set "device_target_build=10B500"
        set "device_target_vers=6.1.6"
    )
    
    echo !device_type!| findstr /r "^iPhone5,[34]" >nul
    if !errorlevel! EQU 0 (
        set "device_target_build=11D257"
        set "device_target_vers=7.1.2"
    )
    if not "%~1"=="" (
        set "device_target_vers=%~1"
    )
    set "version=!device_target_vers!"
    call :print Ramdisk version:!device_target_vers!
    call :log Check version info

    if "!version!"=="" (
        call :get_firmware_info build !device_target_build!
    ) else (
        call :get_firmware_info ver !version!
    )

    if not "!build_id!"=="" (
        set "device_target_build=!build_id!"
    )
    call :device_fw_key_check

    set "ramdisk_path=%saved%\!device_type!\ramdisk_!device_target_build!"

    set "files_missing=0"
    if exist "!ramdisk_path!" (
        for %%f in (Ramdisk.dmg DeviceTree.dec Kernelcache.dec) do (
            if not exist "!ramdisk_path!\%%f" (
                set "files_missing=1"
            )
        )
    ) else (
        set "files_missing=1"
    )

    if "!files_missing!"=="1" (
        rd /s /q "!ramdisk_path!" 2>nul
    ) else (
        call :log Make ramdisk successfully
        call :ramdisk_boot
        exit /b 0
    )

    md "!ramdisk_path!" 2>nul

    for %%g in (!comps!) do (
        set "getcomp=%%g"
        set "name="
        set "iv="
        set "key="

        (echo !device_fw_key!) > ".\fw_key.json"
        
        for /f "delims=" %%i in ('%jq% -j ".keys[] | select(.image == \"!getcomp!\") | .filename" "fw_key.json"') do set "name=%%i"
        for /f "delims=" %%i in ('%jq% -j ".keys[] | select(.image == \"!getcomp!\") | .iv" "fw_key.json"') do set "iv=%%i"
        for /f "delims=" %%i in ('%jq% -j ".keys[] | select(.image == \"!getcomp!\") | .key" "fw_key.json"') do set "key=%%i"
        
        del "fw_key.json" 2>nul

        set "path_prefix="
        if "!getcomp!"=="iBSS" set "path_prefix=Firmware/dfu/"
        if "!getcomp!"=="iBEC" set "path_prefix=Firmware/dfu/"
        if "!getcomp!"=="DeviceTree" (
            set "path_prefix=Firmware/all_flash/"
            echo !build_id!| findstr /r "^14[EFG]" >nul
            if !errorlevel! NEQ 0 set "path_prefix=!all_flash!/"
        )

        if not defined name (
            set "hwmodel=!device_model!"
            echo !build_id!| findstr /r "^14[EFG]" >nul
            if !errorlevel! EQU 0 (
                echo !device_type!| findstr /r "^iPhone5,[12]" >nul && set "hwmodel=iphone5"
                echo !device_type!| findstr /r "^iPhone5,[34]" >nul && set "hwmodel=iphone5b"
                echo !device_type!| findstr /r "^iPad3,[456]" >nul && set "hwmodel=ipad3b"
            ) else (
                echo !build_id!| findstr /r "^[789] ^10 ^11" >nul && set "hwmodel=!hwmodel!ap"
            )
            
            if "!getcomp!"=="iBSS" set "name=!getcomp!.!hwmodel!.RELEASE.dfu"
            if "!getcomp!"=="iBEC" set "name=!getcomp!.!hwmodel!.RELEASE.dfu"
            if "!getcomp!"=="DeviceTree" set "name=!getcomp!.!device_model!ap.img3"
            if "!getcomp!"=="Kernelcache" set "name=kernelcache.release.!hwmodel!"
        )

        call :log !getcomp!
        if exist "!ramdisk_path!\!name!" (
            copy /y "!ramdisk_path!\!name!" . >nul
        ) else (
            call :pzb "%url%" "!path_prefix!!name!" "." "!name!"
        ) 

        if not exist "!name!" (
            echo Failed to get !name!. Please run the script again.
            exit /b 1
        )
        if not exist "!ramdisk_path!\!name!" (
            copy /y "!name!" "!ramdisk_path!\" >nul
        )

        move /y "!name!" "!getcomp!.orig" >nul
        
        set "is_old_proc=0"
        if !device_proc! EQU 1 set "is_old_proc=1"
        if "!device_type!"=="iPod2,1" set "is_old_proc=1"

        if "!getcomp!"=="Kernelcache" ( set "do_old=1" ) else if "!getcomp!"=="iBSS" ( set "do_old=1" ) else ( set "do_old=0" )

        if !is_old_proc! EQU 1 (
            if !do_old! EQU 1 (
                cmd /c ""%xpwntool%" !getcomp!.orig !getcomp!.dec -iv !iv! -k !key!"
            ) else (
                echo !build_id!| findstr /r "^14" >nul
                if !errorlevel! EQU 0 (
                    copy /y !getcomp!.orig !getcomp!.dec >nul
                ) else (
                    cmd /c ""%xpwntool%" !getcomp!.orig !getcomp!.dec -iv !iv! -k !key! -decrypt"
                )
            )
        ) else (
            echo !build_id!| findstr /r "^14" >nul
            if !errorlevel! EQU 0 (
                copy /y !getcomp!.orig !getcomp!.dec >nul
            ) else (
                cmd /c ""%xpwntool%" !getcomp!.orig !getcomp!.dec -iv !iv! -k !key! -decrypt"
            )
        )
    )

    call :log Patch RestoreRamdisk
    cmd /c ""%xpwntool%" RestoreRamdisk.dec Ramdisk.raw"
    if !device_proc! NEQ 1 (
        cmd /c ""%hfsplus%" Ramdisk.raw grow 30000000"
        cmd /c ""%hfsplus%" Ramdisk.raw untar ..\resources\sbplist.tar"
    )

    if !device_proc! EQU 1 (
        cmd /c ""%dir%\bspatch.exe" Ramdisk.raw Ramdisk.patched ..\resources\patch\018-6494-014.patch"
        cmd /c ""%xpwntool%" Ramdisk.patched Ramdisk.dmg -t RestoreRamdisk.dec"
        call :log Patch iBSS
        cmd /c ""%dir%\bspatch.exe" iBSS.orig iBSS ..\resources\patch\iBSS.!device_model!ap.RELEASE.patch"
        call :log Patch Kernelcache
        move /y Kernelcache.dec Kernelcache0.dec >nul
        cmd /c ""%dir%\bspatch.exe" Kernelcache0.dec Kernelcache.patched ..\resources\patch\kernelcache.release.s5l8900x.patch"
        cmd /c ""%xpwntool%" Kernelcache.patched Kernelcache.dec -t Kernelcache.orig -iv !iv! -k !key!"
        del /f /q DeviceTree.dec 2>nul
        move /y DeviceTree.orig DeviceTree.dec >nul
    ) else if "!device_type!"=="iPod2,1" (
        cmd /c ""%hfsplus%" Ramdisk.raw untar ..\resources\ssh_old.tar"
        cmd /c ""%xpwntool%" Ramdisk.raw Ramdisk.dmg -t RestoreRamdisk.dec"
        call :log Patch iBSS
        cmd /c ""%dir%\bspatch.exe" iBSS.dec iBSS.patched ..\resources\patch\iBSS.!device_model!ap.RELEASE.patch"
        cmd /c ""%xpwntool%" iBSS.patched iBSS -t iBSS.orig"
        call :log Patch Kernelcache
        move /y Kernelcache.dec Kernelcache0.dec >nul
        cmd /c ""%dir%\bspatch.exe" Kernelcache0.dec Kernelcache.patched ..\resources\patch\kernelcache.release.!device_model!.patch"
        cmd /c ""%xpwntool%" Kernelcache.patched Kernelcache.dec -t Kernelcache.orig -iv !iv! -k !key!"
        del /f /q DeviceTree.dec 2>nul
        move /y DeviceTree.orig DeviceTree.dec >nul
    ) else (
        cmd /c ""%hfsplus%" Ramdisk.raw untar ..\resources\ssh.tar"
        if "%~1"=="jailbreak" (
            echo !device_vers!| findstr /r "^8" >nul
            if !errorlevel! EQU 0 cmd /c ""%hfsplus%" Ramdisk.raw untar ..\resources\jailbreak\daibutsu\bin.tar"
        )
        cmd /c ""%hfsplus%" Ramdisk.raw mv sbin/reboot sbin/reboot_bak"
        cmd /c ""%hfsplus%" Ramdisk.raw mv sbin/halt sbin/halt_bak"
        
        echo !build_id!| findstr /r "^12 ^13 ^14" >nul
        if !errorlevel! EQU 0 (
            copy /y ..\resources\restored_external .\restored_external >nul
            cmd /c ""%hfsplus%" Ramdisk.raw mv usr/local/bin/restored_external usr/local/bin/restored_external_o"
            cmd /c ""%hfsplus%" Ramdisk.raw add restored_external usr/local/bin/restored_external"
            cmd /c ""%hfsplus%" Ramdisk.raw chmod 755 usr/local/bin/restored_external"
            cmd /c ""%hfsplus%" Ramdisk.raw chown 0:0 usr/local/bin/restored_external"
        )
        
        if "!just_password!"=="1" (
            if "!just_password_legacy!" NEQ "1" (
                echo !build_id!| findstr /r "^12 ^13 ^14" >nul
                if !errorlevel! EQU 0 (
                    cmd /c ""%hfsplus%" Ramdisk.raw mv usr/local/bin/restored_external usr/local/bin/restored_external.real"
                    copy /y ..\resources\bruteforce\setup.sh .\restored_external >nul
                    cmd /c ""%hfsplus%" Ramdisk.raw add restored_external usr/local/bin/restored_external"
                    cmd /c ""%hfsplus%" Ramdisk.raw chmod 755 usr/local/bin/restored_external"
                    cmd /c ""%hfsplus%" Ramdisk.raw chown 0:0 usr/local/bin/restored_external"
                )
                cmd /c ""%hfsplus%" Ramdisk.raw rm usr/local/bin/restored_external.real"
                copy /y ..\resources\bruteforce\restored_external .\restored_external.sshrd >nul
                cmd /c ""%hfsplus%" Ramdisk.raw add restored_external.sshrd usr/local/bin/restored_external.sshrd"
                cmd /c ""%hfsplus%" Ramdisk.raw chmod 755 usr/local/bin/restored_external.sshrd"
                copy /y ..\resources\bruteforce\bruteforce . >nul
                cmd /c ""%hfsplus%" Ramdisk.raw add bruteforce usr/bin/bruteforce"
                cmd /c ""%hfsplus%" Ramdisk.raw chmod 755 usr/bin/bruteforce"
                copy /y ..\resources\bruteforce\setup.sh .\restored_external >nul
                cmd /c ""%hfsplus%" Ramdisk.raw add restored_external usr/local/bin/restored_external"
                cmd /c ""%hfsplus%" Ramdisk.raw chmod 755 usr/local/bin/restored_external"
                cmd /c ""%hfsplus%" Ramdisk.raw chown 0:0 usr/local/bin/restored_external"
            )
        )
        cmd /c ""%xpwntool%" Ramdisk.raw Ramdisk.dmg -t RestoreRamdisk.dec"

        call :log Patch iBSS
        cmd /c ""%xpwntool%" iBSS.dec iBSS.raw"
        set "device_boot4=0"
        if "!device_type:~0,5!"=="iPad2" ( set "is_ipad2=1" ) else ( set "is_ipad2=0" )
        if "!device_type!"=="iPhone3,3" ( set "do_chk4=1" ) else if !is_ipad2! EQU 1 ( set "do_chk4=1" ) else ( set "do_chk4=0" )
        if !do_chk4! EQU 1 (
            echo !build_id!| findstr /r "^8[FGHJKL] 8E600 8E501" >nul
            if !errorlevel! EQU 0 set "device_boot4=1"
        )
        if !device_boot4! EQU 1 (
            cmd /c ""%iBoot32Patcher%" iBSS.raw iBSS.patched --rsa --debug -b "-v amfi=0xff cs_enforcement_disable=1""
        ) else (
            cmd /c ""%iBoot32Patcher%" iBSS.raw iBSS.patched --rsa --debug -b "!device_bootargs!""
        )
        cmd /c ""%xpwntool%" iBSS.patched iBSS -t iBSS.dec"
        
        call :log Patch iBEC
        cmd /c ""%xpwntool%" iBEC.dec iBEC.raw"
        cmd /c ""%iBoot32Patcher%" iBEC.raw iBEC.patched --rsa --debug -b "rd=md0 -v amfi=0xff amfi_get_out_of_my_way=1 cs_enforcement_disable=1 pio-error=0""
        cmd /c ""%xpwntool%" iBEC.patched iBEC -t iBEC.dec"
    )

    if !device_boot4! EQU 1 (
        call :log Patch Kernelcache
        move /y Kernelcache.dec Kernelcache0.dec >nul
        cmd /c ""%xpwntool%" Kernelcache0.dec Kernelcache.raw"
        cmd /c ""%dir%\bspatch.exe" Kernelcache.raw Kernelcache.patched ..\resources\patch\kernelcache.release.!device_model!.!build_id!.patch"
        cmd /c ""%xpwntool%" Kernelcache.patched Kernelcache.dec -t Kernelcache0.dec"
    )

    for %%f in (iBSS iBEC DeviceTree.dec Kernelcache.dec Ramdisk.dmg) do (
        if exist "%%f" move /y "%%f" "!ramdisk_path!\" >nul
    )
    call :ramdisk_boot
    exit /b 0

:ramdisk_boot
    if "!device_argmode!"=="none" (
        if !device_proc!=="6" (
            call :warn A6 device does not support boot,please waiting for update
        )
        call :print Done creating SSH ramdisk files: saved/!device_type!/ramdisk_!build_id!
        exit /b
    )
    call :yesno "Do you want to boot?"
    if "!yesno!"=="0" (
        call :print Done creating SSH ramdisk files: saved/!device_type!/ramdisk_!build_id!
        exit /b
    ) else (
        call :print Done creating SSH ramdisk files: saved/!device_type!/ramdisk_!build_id!
    )

    if "!device_proc!"=="4" if "!build_id:~0,1!" GEQ "7" if "!build_id:~0,1!" LSS "9" (
        call :warn Boot iOS 3 or 4 ramdisk may cause boot loop
        call :yesno
        if !yesno!=="0" (
            exit /b
        )
    )

    if not defined device_pwnd (
        call :device_pwn
    )
    
    set "is_ipad1=0"
    if "!device_type!"=="iPad1,1" set "is_ipad1=1"
    
    if !is_ipad1! EQU 1 (
        echo !build_id!| findstr /r "^9" >nul
        if !errorlevel! NEQ 0 (
            call :patch_ibss
            call :print Sending iBSS...
            %irecovery% -f pwnediBSS.dfu
            timeout /t 2 >nul
            call :print Sending iBEC...
            %irecovery% -f "!ramdisk_path!\iBEC"
        )
    ) else if !device_proc! LSS 5 (
        if "!device_pwnrec!" NEQ "1" (
            call :print Sending iBSS...
            %irecovery% -f "!ramdisk_path!\iBSS"
        )
    )

    timeout /t 2 >nul
    set "is_old_proc=0"
    if !device_proc! EQU 1 set "is_old_proc=1"
    if "!device_type!"=="iPod2,1" set "is_old_proc=1"
    if !is_old_proc! NEQ 1 (
        call :print Sending iBEC...
        %irecovery% -f "!ramdisk_path!\iBEC"
        if "!device_pwnrec!"=="1" (
            %irecovery% -c "go"
        )
    )
    call :checkmode rec 20
    call :print Sending ramdisk...
    "%irecovery%" -f "!ramdisk_path!\Ramdisk.dmg"
    call :print Running ramdisk
    %irecovery% -c "getenv ramdisk-delay"
    %irecovery% -c "ramdisk"
    timeout /T 1 /NOBREAK > nul 2>&1
    call :print Sending DeviceTree...
    "%irecovery%" -f "!ramdisk_path!\DeviceTree.dec"
    call :print Running devicetree
    %irecovery% -c "devicetree"
    timeout /T 1 /NOBREAK > nul 2>&1
    call :print Sending KernelCache...
    "%irecovery%" -f "!ramdisk_path!\Kernelcache.dec"
    %irecovery% -c "bootx"

    call :log Booting, please wait...
    timeout /t 6 >nul

    if "!just_boot!"=="1" (
        call :log Done, use script to connect device
        endlocal
        exit /b 0
    ) else (
        if "%~1" NEQ "" (
            call :device_iproxy
        ) else (
            call :device_iproxy "no-logging"
        )
        
        set "found="
        call :log Waiting for device...
        call :log You may need to unplug and replug your device.
        set /a try_cnt=0
    )
    call :ssh_check
    exit /b

:ssh_check
    for /f "delims=" %%i in ('%ssh% -p !ssh_port! root@127.0.0.1 "echo 1" 2^>nul') do set "found=%%i"
    set /a try_cnt+=1
    
    if "!found!"=="1" (
        set "do_trans=0"
        if !device_proc! EQU 1 set "do_trans=1"
        if "!device_type!"=="iPod2,1" set "do_trans=1"

        if !do_trans! EQU 1 (
            call :log Transferring some files
            cmd /c ""%dir%\tar.exe" -xvf ..\resources\ssh.tar ./bin/chmod ./bin/chown ./bin/cp ./bin/dd ./bin/mount.sh ./bin/tar ./usr/bin/date ./usr/bin/df ./usr/bin/du"
            %ssh% -p !ssh_port! root@127.0.0.1 rm -f /bin/mount.sh /usr/bin/date
            cmd /c "%scp% -P !ssh_port! bin/* root@127.0.0.1:/bin"
            cmd /c "%scp% -P !ssh_port! usr/bin/* root@127.0.0.1:/usr/bin"
        )
        goto menu
    )

    if !try_cnt! EQU 10 (
        call :error Unable to connect SSH, please try boot again
        endlocal
        exit /b 1
    )
    timeout /t 2 >nul
    goto :ssh_check


:ssh_message
    call :print "* For accessing data, note the following:"
    call :print "* Host: sftp://127.0.0.1 | User: root | Password: alpine | Port: !ssh_port!"
    call :print "* Other Useful SSH Ramdisk commands:"
    call :print "* Clear NVRAM with this command:"
    call :print     "nvram -c"
    call :print "* Erase All Content and Settings with this command (iOS 9+ only):"
    call :print     "nvram oblit-inprogress=5"
    call :print "* To reboot, use this command:"
    call :print     "reboot_bak"
    call :print "* Remove Setup.app:"
    call :print     "rm -rf /mnt1/Applications/Setup.app"
    !ssh! -p !ssh_port! root@127.0.0.1
    endlocal
    exit /b 0

:menu
    setlocal enabledelayedexpansion
    cls
    echo *** SSHRD_Script_32Bit ***
    echo - Script by MrY0000 -
    echo - Thanks LuckZGD Setup.app -
    echo - Forked from Legacy-iOS-Kit(https://github.com/LukeZGD/Legacy-iOS-Kit) -
    echo Select option:
    set "options=SSH Connection"
    set "options=!options! Exit"
    call :select_option "menu_select" "SSH Connection" "Exit"
    if "!selected!"=="SSH Connection" (
        call :ssh_message
    ) else if "!selected!"=="Exit" (
        set exit="1"
        exit /b 0
    )
    if not !exit!=="1" (
        goto menu
    )
    exit /b 0

:jailbreak


:select_option
    set "selected="
    setlocal enabledelayedexpansion

    set "_out_var=%~1"
    if not defined _out_var exit /b 1
    shift
    set "_cn=0"

    :menu_parse_loop
        if "%~1"=="" goto :menu_parse_done
        set "_menu[!_cn!]=%~1"
        set /a _cn+=1
        shift
        goto :menu_parse_loop
    :menu_parse_done

    if %_cn% equ 0 exit /b 1
    for /f %%a in ('echo prompt $E^|cmd') do set "_ESC=%%a"
    set "_pointer=--> "
    set "_blank=    "
    set /a _max_idx=_cn-1
    set /a _i=_cn*10000
    set "_mod=0"
    <nul set /p "=!_ESC![?25l"

:menu_draw
    for /l %%k in (0,1,!_max_idx!) do (
        if %%k==!_mod! (
            echo !_ESC![7m!_pointer!!_menu[%%k]!!_ESC![0m!_ESC![K
        ) else (
            echo !_blank!!_menu[%%k]!!_ESC![K
        )
    )

:menu_get_key
    for /f "delims=" %%i in ('powershell -Command "[Console]::ReadKey($true).Key"') do set "_key=%%i"

    if /i "!_key!"=="UpArrow" (
        set /a _i-=1
        set /a _mod=_i%%_cn
        <nul set /p "=!_ESC![!_cn!A"
        goto :menu_draw
    )

    if /i "!_key!"=="DownArrow" (
        set /a _i+=1
        set /a _mod=_i%%_cn
        <nul set /p "=!_ESC![!_cn!A"
        goto :menu_draw
    )
    if /i "!_key!"=="Enter" goto :menu_selected
    goto :menu_get_key

:menu_selected
    <nul set /p "=!_ESC![?25h"
    for /f "delims=" %%V in ("!_menu[%_mod%]!") do (
        endlocal
        set "%_out_var%=%_mod%"
        set "selected=%%~V"
        exit /b 0
    )

:yesno
    set "yesno="
    if "%~1"=="" (
        call :print Do you want to continue?
    ) else (
        call :print %~1
    )
    if "%~2"=="1" (
        call :select_option yesno "Yes" "No"
    ) else (
        call :select_option yesno "No" "Yes"
    )
    
    if "!yesno!"=="0" exit /b 0
    exit /b 1
    