@echo off
setlocal enabledelayedexpansion

for /f "delims=" %%i in ('%1 2^>^&1') do (
    rem 逐行输出，%%i 代表当前行，自带换行效果
    echo %%i
)