@echo off
cls
echo ********************************************************************************
echo ****                       DOSCRYPT EXAMPLE BATCH FILE                      ****
echo ****                       ___________________________                      ****
echo ****                                                                        ****
echo ****          This is an example of how DOSCRYPT can encrypt a file.        ****
echo ********************************************************************************
pause
..\BINARIES\WIN\DOSCRYPT32.EXE ALICE.TXT ALICE.AES

IF EXIST "ALICE.AES" GOTO OK

echo.
echo There was a problem while executing the example. Encrypted file not created!.
echo.
goto quit

:OK

echo.
echo Encrypted file created sucessfully!
echo.

:QUIT
