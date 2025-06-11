@echo OFF
cls
setlocal enableDelayedExpansion

for /f "delims=" %%i in ('build\static-mt\builds\debug\sha256 test.txt') do (
	set hash=%%i
)

if %ERRORLEVEL% neq 0 (
	echo Sha256 failed with errorcode: %ERRORLEVEL%
	exit /b %ERRORLEVEL%
)

echo   Result: !hash!
echo Expected: 72d96ae975966e6d55867f9e7f802dcd95171759bb3096693c2738f6f25b4683

if "%hash%" == "72d96ae975966e6d55867f9e7f802dcd95171759bb3096693c2738f6f25b4683" (
	echo SUCCESS. Same Hash!
) else (
	echo FAILED. Different Hash!
)