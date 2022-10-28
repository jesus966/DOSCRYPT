# Welcome to DOSCRYPT 👋
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg?cacheSeconds=2592000) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](MIT)

> DOSCRYPT is a program that encrypt/decrypts files for MS-DOS, made to demonstrate the use of the tiny-AES and SHA-256 C libraries for the cybersecurity master of the University of Seville.

## Setup and use of DOSCRYPT
DOSCRYPT doesn't need any setup at all. It works simply using the suitable version. In this moment, there are version for true 16-bit MS-DOS and modern 32-64 bits versions that works on Windows.

You can find the binaries in the BINARIES\OLD for the 16-bit MS-DOS version, or in BINARIES\WIN for 32 and 64 bits versions for modern systems.

It's a very simple program, for example, typing DOSCRYPT.EXE /? gives the following help screen:

```sh
>DOSCRYPT /?

Encrypts or decrypts a file using AES-256.

Use:

DOSCRYPT.EXE [/?] [/D] [/S] [/V] [/P][passphrase] SOURCE DEST

/?                     Shows this help screen.
/D                     Decrypts the given file.
/S                     Silent mode.
/V                     Verbose mode.
/P PASSPHRASE          Set the passphrase to encrypt or decrypt.
SOURCE                 Source file to encrypt or decrypt.
DEST                   Encrypted or decrypted destination file.

```

The program needs a source (file to encrypt/decrypt) and a destination file.
	
Default mode is encryption mode. To decrypt a file, use the /D parameter.
	
The /S parameter puts DOSCRYPT in silent mode. It will not echo anything to the screen or ask for user input.

The /V parameter will show extra information on screen of the encrypt/decrypt process, like the file block size, the actual key used for the algorithm, the initialization vector and the padding applied to the last block of data.
	
The /P parameter sets a passphrase to avoid ask it to the user.

## Return codes

To make easy using this program with batch scripts, DOSCRYPTS returns a code with the following meaning:

|CODE | MEANING |		
| ------ | ------ |
|0    | Program ended successfully. |
|1    | Help was displayed on screen. |
|2    | Invalid parameters send to the program. |
|3    | I/O error while reading/writing to file. |
|4    | Invalid file format detected. |
|5    | Invalid passphrase. |
|6    | Out of memory. |

## How to build
For building this project, you can use Borland Turbo C++ 3.0 to generate the old MS-DOS compatible version. Download all the files, cd to the BUILD folder and type make.

You can also generate a mode modern executable using tiny C compiler, and deleting the typedef definitions on SHA256.H in DEP folder.

## How DOSCRYPT works
DOSCRYPT uses AES-256-CBC algorithm to encrypt/decrypt files.
    
The key used in the algorithm is derived from the SHA-256 hash of the passphrase. It also generates a "random" IV vector for the algorithm.
    
In every encrypted file, there is a file header that contains a signature, a file version, the encrypt mode (only CBC for now), the IV vector and a encrypted magic word ("PASSPHRASEOK") to verify that the introduced passphrase is OK.
    
Thanks to this header information, the program can decrypt any previous encrypted file when necessary.
	
## Author

👤 **Jesús Fernández Gamito**

* Website: www.rtcvalvulas.com
* Github: [@jesus966](https://github.com/jesus966)
* LinkedIn: [@jesus-fdez-gamito](https://linkedin.com/in/jesus-fdez-gamito)

## Thanks

Special thanks to:

* Tiny AES https://github.com/kokke/tiny-AES-c
* SHA-2 https://github.com/amosnier/sha-2

## 🤝 Contributing

Contributions, issues and feature requests are welcome!

## Show your support

Give a ⭐️ if this project helped you!

## 📝 License

Copyright © 2022 [Jesús Fernández Gamito](https://github.com/jesus966).

This project is [MIT](https://opensource.org/licenses/MIT) licensed.

***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_