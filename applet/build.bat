@echo off

if "%1"=="" (
    echo Please provide a parameter.
    exit /b
)

cd ..
call .\apache-ant-1.10.9\bin\ant.bat %1