#include<iostream>
#include<fstream>
#include<sstream>
#include<string>
using namespace std;

#include"cryptopp/cryptlib.h"
#include"cryptopp/hex.h"
#include"cryptopp/filters.h"
#include"cryptopp/des.h"
#include"cryptopp/aes.h"
#include"cryptopp/modes.h"

using namespace CryptoPP;

void des_encryption_8(unsigned char* input, unsigned char* key, unsigned char* xorBlock, unsigned char* output)
{
	DESEncryption desEncryptor;
	desEncryptor.SetKey(key, 8);
	for (int i = 0; i < 8; i++) {
		input[i] = input[i] ^ xorBlock[i];
	}
	desEncryptor.ProcessBlock(input, output);
}

void des_decryption_8(unsigned char* input, unsigned char* key, unsigned char* xorBlock, unsigned char* output)
{
	DESDecryption desDecryptor;
	desDecryptor.SetKey(key, 8);
	desDecryptor.ProcessBlock(input, output);
	for (int i = 0; i < 8; i++) {
		output[i] = output[i] ^ xorBlock[i];
	}
}

int main()
{
	//assign initial variables
	unsigned char keyC[DES::DEFAULT_KEYLENGTH];
	unsigned char xorBlock[DES::BLOCKSIZE];
	unsigned char input[DES::BLOCKSIZE];
	unsigned char output[DES::BLOCKSIZE];
	byte key[DES::DEFAULT_KEYLENGTH] = { 0x14, 0x0b, 0xb2, 0x2a, 0xb4, 0x06, 0xb6, 0x74 };
	byte iv[DES::BLOCKSIZE] = { 0x4c, 0xa0, 0x0f, 0xd6, 0xdb, 0xf1, 0xfb, 0x28 };
	string plain = "0x00112233445566778899AABBCCDDEEFF";
	string prefix = plain.substr(0, 2);
	string ciphertext = "";
	string plaintext = "";

	// Pad the plaintext and output for testing
	int paddedsize = 8;
	if (plain.length() % 8 != 0) {
		int mod = 8 - (plain.length() % 8);
		if (mod != 0) {
			paddedsize = mod;
		}
	}
	for (int i = 0; i < paddedsize; i++) {
		plain = plain + (char)paddedsize;
	}
	cout << "Plaintext after padding: " << plain << endl;

	//Convert key to char, set xorBlock to iv
	for (int i = 0; i < 8; i++) {
		keyC[i] = (unsigned char)key[i];
		xorBlock[i] = (unsigned char)iv[i];
	}

	//output key and IV
	cout << "Key: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)keyC[i];
	}
	cout << "\n" << endl;
	cout << "IV: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)xorBlock[i];
	}
	cout << "\n" << endl;

	//output that encryption is beginning
	cout << "\n" << endl;
	cout << "ENCRYPTING!" << endl;
	
	//encode the whole plain text string
	do {
		for (int i = 0; i < 8; i++) {
			input[i] = (unsigned char)plain[i];
		}
		des_encryption_8(input, keyC, xorBlock, output);
		for (int i = 0; i < 8; i++) {
			ciphertext = ciphertext + (char)output[i];
			xorBlock[i] = output[i];
		}
		plain = plain.erase(0, 8);
	} while (plain.length() != 0);

	//output the ciphertext produced
	cout << "ciphertext: " << ciphertext << endl;

	//reset xorblock to iv
	for (int i = 0; i < 8; i++) {
		xorBlock[i] = (unsigned char)iv[i];
	}

	//output that encryption is beginning
	cout << "\n" << endl;
	cout << "DECRYPTING!" << endl;

	//Decrypt the whole ciphertext string
	do {
		for (int i = 0; i < 8; i++) {
			input[i] = (unsigned char)ciphertext[i];
		}
		des_decryption_8(input, keyC, xorBlock, output);
		for (int i = 0; i < 8; i++) {
			plaintext = plaintext + (char)output[i];
			xorBlock[i] = input[i];
		}
		ciphertext = ciphertext.erase(0, 8);
	} while (ciphertext.length() != 0);

	//Depad the plaintext retrieved
	int depadding = (int)plaintext.at(plaintext.length() - 1);
	plaintext = plaintext.substr(0, plaintext.length() - depadding);
	cout << "Plaintext retrieved: " << plaintext << endl;
}
