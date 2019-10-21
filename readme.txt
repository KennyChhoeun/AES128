
Kenny Chhoeun
AES128bit Project
CS 4600 Crytography and Information Security
Prof. Atanasio

Written in C++, compiled using g++ compiler
Header file: AES128.h
Source file: AES128.cpp

compilation instructions
using g++ compiler
```
g++ -o AES128Encrypt AES128.cpp

```
executable will be named AES128Encrypt
can be run by entering: "./AES128Encrypt <filename_to_be_encrypted.txt>" into the terminal

Program accepts a 16 byte key each byte must seperated by spaces to have an intended outcome
eg. 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10

if running on windows, user input may not work because disabling echo
may only be a OS specific thing, i could not test because i am working with a *nix based machine.
