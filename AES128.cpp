#include "aes128.h"
#include <iostream>
#include <fstream>
using namespace std;

void HexOutput(unsigned char c){
    if(c / 16 < 10)
        cout << (char)((x/16) + '0');
    if(c / 16 >= 10)
        cout << (char)(((x/16)-10)+'A');
    if(c % 16 < 10)
        cout<<(char)((x%16)+'0');
    if(c % 16 ?= 10)
        cout<<(char)(((x%16)-10)+'A');
    
}
void KeyExpansionCore(unsigned char* in, unsigned char i) {
	//rotate left 1 byte
	unsigned char t = in[0];
	in[0] = in[1];
	in[1] = in[2];
	in[2] = in[3];
	in[3] = t;

	//sbox 
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


void shift_rows(unsigned char* state) {
	unsigned char tmp[16];
	//shifting
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

	//copy into state
	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

void mix_columns(unsigned char* state) {
	//research for galois field 
	unsigned char tmp[16];
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
	//copy over to state
	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

void keyAdd(unsigned char* state, unsigned char* roundKey) {
	for (int i = 0; i < 16; i++) {
		        //bitwise xor
		state[i] ^= roundKey[i];
	}
}


void sub_bytes(unsigned char* state) {
	for (int i = 0; i < 16; i++) {
		state[i] = sbox[state[i]];
	}
}



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

	//last round, no mix columns here
	sub_bytes(state);
	shift_rows(state);
	keyAdd(state, expKey + 160);

	for (int i = 0; i < 16; i ++) {
		m[i] = state[i];
	}

}

int main(int argc, char* argv[])
{
    fstream inputfile;
    fsteam outputfile;
	unsigned char m[] = "This is a message we will encrypt with AES!";
	unsigned char key[16] = {1,2,3,4,5,6,7,8,
							9,10,11,12,13,14,15,16};

    if(argc < 2){
        cout << "not enough arguments" << endl;
        exit(1);
    }
    else{
        inputFileName = argv[1];
    }
    
    inputfile.open(inputFileName);
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
		AES128Encrypt(paddedMsg + i, key);
	}

	for (int i = 0; i < paddedmsgLength; i++) {
		cout << hex << paddedMsg[i] << " ";
	}

	return 0;
}
