@echo off
cls
echo ********************************************************************************
echo ****                       DOSCRYPT EXAMPLE BATCH FILE                      ****
echo ****                       ___________________________                      ****
echo ****                                                                        ****
echo ****          This is an example of how DOSCRYPT can decrypt a file.        ****
echo ********************************************************************************
pause
IF EXIST "DECALICE.TXT" GOTO DELETE
IF EXIST "ALICE.AES" GOTO OK

:DELETE
echo.
echo Cleaning files for the example...
echo.
del DECALICE.TXT
IF EXIST "ALICE.AES" GOTO OK

echo.
echo ALICE.AES encrypted file not found, run ENCRYPT.BAT first!.
echo.
goto quit

:OK
..\BINARIES\WIN\DOSCRYPT64.EXE ALICE.AES DECALICE.TXT /D

IF EXIST "DECALICE.TXT" GOTO OKDEC

echo.
echo There was a problem while executing the example. Unable to decrypt file!.
echo.
goto quit

:OKDEC
echo.
echo File decrypted sucessfully!.
echo.

:QUIT
