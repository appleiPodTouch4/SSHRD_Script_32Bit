@echo off

goto main

:main
    call :log "hello 11"
    call :log hello 11
    pause
    
:log
    setlocal DisableDelayedExpansion
    set "msg=%*"
    if defined msg set "msg=%msg:"=%"
    echo [Log] %msg%
    exit /b

:error
    setlocal DisableDelayedExpansion
    set "msg=%*"
    if defined msg set "msg=%msg:"=%"
    echo [ERROR] %msg%
    exit /b

:warn
    setlocal DisableDelayedExpansion
    set "msg=%*"
    if defined msg set "msg=%msg:"=%"
    echo [WARNING] %msg%
    exit /b

:print
    setlocal DisableDelayedExpansion
    set "msg=%*"
    if defined msg set "msg=%msg:"=%"
    echo [*] %msg%
    exit /b
