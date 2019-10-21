/*author: Kenny Chhoeun
 CS 4600: Cryptography and Information Security
 Prof. Atanasio
 Project: AES128 Encryption Implementation
*/
#include "AES128.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string>
#include <termios.h>
#include <unistd.h>
using namespace std;

// Doing research, I believe these methods of hiding keystrokes
// are operating system specific
// so they more than likely will not work on a windows
// based machine, only _nux machines which is what I happen to be running
void hide_Keystrokes()
{
    //part of termois.h
    termios tty;
    //uses unistd.h
    tcgetattr(STDIN_FILENO, &tty);
    //disabling echo and keystroke
    tty.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

void show_Keystrokes()
{
    //part of termois.h
    termios tty;
    //uses unistd.h
    tcgetattr(STDIN_FILENO, &tty);
    //enable echo back so terminal works normally
    tty.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

//function to create the file name with new extension
void fileExtension(string& s, const string& newExt){
    string::size_type i = s.rfind('.',s.length());
    if(i!=string::npos) {
        s.replace(i+1, newExt.length(), newExt);
    }
}

void KeyExpansionCore(unsigned char* in, unsigned char i) {
	//rotate left
	unsigned char t = in[0];
	in[0] = in[1];
	in[1] = in[2];
	in[2] = in[3];
	in[3] = t;

	//sbox in AES128.h//
	in[0] = sbox[in[0]];
	in[1] = sbox[in[1]];
	in[2] = sbox[in[2]];
	in[3] = sbox[in[3]];

	//round constant rCon (only need the first few for aes128)
		//bitwise xor
	in[0] ^= rcon[i];
}

void KeyExp(unsigned char* inputKey, unsigned char* expKey){
	//rotate
	//s-box
	//rcon
	//1st 128 bits are the original key///
	for (int i = 0; i < 16; i++) {
		expKey[i] = inputKey[i];
	}

	//we need to keep track of Rcon iterations//
	int generated_Bytes = 16; //16 from our for loop
	int iterations = 1;
	unsigned char tmp[4];
    //expanded key
	while (generated_Bytes < 176) {
		for (int i = 0; i < 4; i++) {
			tmp[i] = expKey[i + generated_Bytes - 4];
		}

		//once every 16 bytes we call our KeyExpansionCore
		if (generated_Bytes % 16 == 0) { 
			KeyExpansionCore(tmp, iterations);
			iterations++;
		}

		for (unsigned char i = 0; i < 4; i++) {
			expKey[generated_Bytes] = expKey[generated_Bytes - 16] ^ tmp[i];
			generated_Bytes++;
		}
	}
}
//shift rows function
void shift_rows(unsigned char* state) {
	unsigned char tmp[16];
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];

	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];

	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

	//copy all the temporary values from tmp array to our state array
	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

void mix_columns(unsigned char* state) {
	//research for galois field
    //use the lookup table mul2 and mul3 from AES128.cpp
    //every round except for the last one
	unsigned char tmp[16];
    //all casting to unsigned chars and xor'ed
	tmp[0] = (unsigned char)(mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
	tmp[1] = (unsigned char)(state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
	tmp[2] = (unsigned char)(state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
	tmp[3] = (unsigned char)(mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

	tmp[4] = (unsigned char)(mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
	tmp[5] = (unsigned char)(state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
	tmp[6] = (unsigned char)(state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
	tmp[7] = (unsigned char)(mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

	tmp[8] = (unsigned char)(mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
	tmp[9] = (unsigned char)(state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
	tmp[10] = (unsigned char)(state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
	tmp[11] = (unsigned char)(mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

	tmp[12] = (unsigned char)(mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
	tmp[13] = (unsigned char)(state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
	tmp[14] = (unsigned char)(state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
	tmp[15] = (unsigned char)(mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);
	//copy over the temporary values to the state array
	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}
//key addition layer
void keyAdd(unsigned char* state, unsigned char* roundKey) {
	for (int i = 0; i < 16; i++) {
		        //bitwise xor
		state[i] ^= roundKey[i];
	}
}
//sub bytes layer
void sub_bytes(unsigned char* state) {
	for (int i = 0; i < 16; i++) {
		state[i] = sbox[state[i]];
	}
}

//encryption process
void AES128Encrypt(unsigned char* m, unsigned char* key) {
	unsigned char state[16]; 
	for (int i = 0; i < 16; i++) {
		state[i] = m[i];
	}
	unsigned char expKey[176]; 
	KeyExp(key, expKey); //Key Expansion
	keyAdd(state, key); //Add round key
	int roundNum = 9;

	//round 0-8
	for (int i = 0; i < roundNum; i++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		keyAdd(state, expKey + (16 *(i+1)));
	}

	//last round, no mix is done columns here
	sub_bytes(state);
	shift_rows(state);
	keyAdd(state, expKey + 160);
    
	for (int i = 0; i < 16; i ++) {
		m[i] = state[i];
	}

}


int main(int argc, char* argv[])
{
    ifstream src_filepath;
    ofstream dst_filepath;
    
    string inputFileName;
    
    if (argc < 2) {
        cout << "Not Enough Arguments given, format is " << endl;
        cout << "./AES128Encrypt <file_to_be_encrypted.txt>" << endl;
        exit(1); //if the user started the program wrong they have to restart it
    }
    inputFileName = argv[1];
    //read the input file by binary//
    size_t size;
    src_filepath.open(inputFileName, ios::in | ios::binary|ios::ate);
    char* m = 0;
    src_filepath.seekg(0, ios::end); //pointer ios::ate: at the end
    size = src_filepath.tellg(); //length of the file
    src_filepath.seekg(0, ios::beg);//pointer at beginning
    m = new char[size+1]; //char array pertain to size of input file
    src_filepath.read(m,size);
    m[size] = '\0';

    //print out statements with instructions for the user//
    cout << "\n\n";
    cout << "-----------------128 bit AES ENCRYPTION PROGRAM------------------\n";
    cout << "Please input the 128-bit key in hex values seperated by spaces\n";
    cout << "     e.g 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10\n: ";

    string keyInput;
    hide_Keystrokes();
    getline(cin,keyInput);
    show_Keystrokes();
    //convert the input into chars for the key
    istringstream hex_chars_stream(keyInput);
    unsigned char key[16];
    int i=0;
    unsigned int c;
    
    while(hex_chars_stream >> hex >> c)
    {
        key[i] = c; //add to the key array
        i++;
    }
    
    fileExtension(inputFileName, "enc");
    //call function that will create a output
    //file with same name
    //with but with different extension we pass as the second argument
    //updates inputFileName value
    
    //padding
	int msglength = strlen((const char*)m);
	int paddedmsgLength = msglength;

	if (paddedmsgLength % 16 != 0) {//round to nearest multiple of 16
		paddedmsgLength = (paddedmsgLength / 16 + 1) * 16;
	}

	unsigned char* paddedMsg = new unsigned char[paddedmsgLength];
    
	for (int i = 0; i < paddedmsgLength; i++) {
		if (i >= msglength)
			paddedMsg[i] = 0;
		else
			paddedMsg[i] = m[i];
	}

	//encrypt padded msg by pasing blocks of 16 bytes to AES128Encrypt()
	for (int i = 0; i < paddedmsgLength; i+=16) {
		AES128Encrypt(paddedMsg+i, key);
	}

    dst_filepath.open(inputFileName, ios::out | ios::binary);
    //prints the result to the file with extension .enc in same directory
    if (dst_filepath.is_open())
    {
        for(int i=0;i<paddedmsgLength;i++){
            dst_filepath << paddedMsg[i];
        }
        dst_filepath.close();
        cout << "Wrote encrypted file to: " << inputFileName <<  endl;
        //tell the user the encryption done to new file
    }
    else
        cout << "Unable to open file";
        //if something where to go wrong
    
    //Free up some memory
    delete[] paddedMsg;
    delete[] m;
    
    cout << "\nEncryption Complete √\n\n" << endl;
	return 0;
}
