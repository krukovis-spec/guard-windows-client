@echo off
rem Build-only helper. Never installs or starts the driver.
call "%~1\BuildEnv\SetupBuildEnv.cmd" amd64
@echo off
if errorlevel 1 exit /b 1
msbuild "%~dp0GuardKernelLab.vcxproj" /nologo /v:minimal /p:Configuration=Release /p:Platform=x64 "/p:OutDir=%~2/bin/" "/p:IntDir=%~2/obj/"
exit /b %errorlevel%
