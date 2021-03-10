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

void des_encryption_8(unsigned char* input, unsigned char* key,
	unsigned char* xorBlock, unsigned char* output)
{

	DESEncryption desEncryptor;
	cout << "Key: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)key[i];
	}
	cout << "." << endl;
	cout << "IV: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)xorBlock[i];
	}
	cout << "." << endl;
	/*cout << "Input Inside: ";
	for (int i = 0; i < 8; i++) {
		cout << input[i];
	}*/
	desEncryptor.SetKey(key, 8);
	for (int i = 0; i < 8; i++) {
		input[i] = input[i] ^ xorBlock[i];
	}
	desEncryptor.ProcessBlock(input, output);
	/*desEncryptor.ProcessAndXorBlock(input, xorBlock, output);
	cout << "." << endl;
	cout << "IV After encryption: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)xorBlock[i];
	}
	cout << "." << endl;
	cout << "Key After encryption: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)key[i];
	}
	cout << "." << endl;
	cout << "Input After XOR: ";
	for (int i = 0; i < 8; i++) {
		cout << input[i];
	}
	cout << "." << endl;
	cout << "Output After encryption: ";
	for (int i = 0; i < 8; i++) {
		cout << output[i];
	}
	cout << "." << endl;*/
}

void des_decryption_8(unsigned char* input, unsigned char* key,
	unsigned char* xorBlock, unsigned char* output)
{
	DESDecryption desDecryptor;
	cout << "Key: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)key[i];
	}
	cout << "." << endl;
	cout << "IV: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)xorBlock[i];
	}
	cout << "." << endl;
	/*
	cout << "Input Inside: ";
	for (int i = 0; i < 8; i++) {
		cout << input[i];
	}*/
	desDecryptor.SetKey(key, 8);
	desDecryptor.ProcessBlock(input, output);
	for (int i = 0; i < 8; i++) {
		output[i] = output[i] ^ xorBlock[i];
	}
	/*cout << "." << endl;
	cout << "IV After encryption: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)xorBlock[i];
	}
	cout << "." << endl;
	cout << "Key After encryption: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)key[i];
	}
	cout << "." << endl;
	cout << "Input After encryption: ";
	for (int i = 0; i < 8; i++) {
		cout << input[i];
	}
	cout << "." << endl;
	cout << "Output After encryption: ";
	for (int i = 0; i < 8; i++) {
		cout << output[i];
	}
	cout << "." << endl;*/
}

int main()
{
	unsigned char keyC[DES::DEFAULT_KEYLENGTH];
	unsigned char xorBlock[DES::BLOCKSIZE];
	unsigned char input[DES::BLOCKSIZE];
	unsigned char output[DES::BLOCKSIZE];
	byte key[DES::DEFAULT_KEYLENGTH] = { 0x14, 0x0b, 0xb2, 0x2a, 0xb4, 0x06, 0xb6, 0x74 };
	byte iv[DES::BLOCKSIZE] = { 0x4c, 0xa0, 0x0f, 0xd6, 0xdb, 0xf1, 0xfb, 0x28 };

	string cipher = "";
	string plain = "";
	// Pad the plaintext
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
	//Convert key to char, set xorBlock to iv, and setup the first input
	for (int i = 0; i < 8; i++) {
		keyC[i] = (unsigned char)key[i];
		xorBlock[i] = (unsigned char)iv[i];
		input[i] = (unsigned char)plain[i];
	}

	//encode the first block
	des_encryption_8(input, keyC, xorBlock, output);
	for (int i = 0; i < 8; i++) {
		cipher = cipher + (char)output[i];
		input[i] = output[i];
	}
	cout << "\n" << endl;
	cout << "ENCRYPTING!" << endl;
	cout << "Ciphertext: " << cipher << endl;
	cipher = "";
	memset(output, 0, sizeof(output));
	des_decryption_8(input, keyC, xorBlock, output);
	for (int i = 0; i < 8; i++) {
		cipher = cipher + (char)output[i];
	}
	cout << "\n" << endl;
	int depadding = (int)cipher.at(cipher.length() - 1);
	cipher = cipher.substr(0, cipher.length() - depadding);
	cout << "DECRYPTING!" << endl;
	cout << "Plaintext retrieved: " << cipher << endl;
}
