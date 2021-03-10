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
	ifstream file1;
	ofstream file2;
	unsigned char keyC[DES::DEFAULT_KEYLENGTH];
	unsigned char xorBlock[DES::BLOCKSIZE];
	unsigned char input[DES::BLOCKSIZE];
	unsigned char output[DES::BLOCKSIZE];
	byte key[DES::DEFAULT_KEYLENGTH] = { 0x14, 0x0b, 0xb2, 0x2a, 0xb4, 0x06, 0xb6, 0x74 };
	byte iv[DES::BLOCKSIZE] = { 0x4c, 0xa0, 0x0f, 0xd6, 0xdb, 0xf1, 0xfb, 0x28 };
	string cipher = "";
	string plaintext = "";

	//file1 is file to read cipher from, file2 is file to write plaintext to
	file1.open("C:/Users/wsucatslabs/source/repos/des_cbc_enc/des_cbc_enc/cipher.txt");
	file2.open("plain.txt");

	//read the ciper and store in cipher string variable
	ostringstream reader;
	reader << file1.rdbuf();
	cipher = reader.str();

	//Convert key to char, set xorBlock to iv
	for (int i = 0; i < 8; i++) {
		keyC[i] = (unsigned char)key[i];
		xorBlock[i] = (unsigned char)iv[i];
	}

	//output that decryption is beginning
	cout << "DECRYPTING!" << endl;

	//output key and IV
	cout << "Key: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)keyC[i];
	}
	cout << endl;
	cout << "IV: ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)xorBlock[i];
	}
	cout << "\n" << endl;

	//Decrypt the whole ciphertext string
	do {
		for (int i = 0; i < 8; i++) {
			input[i] = (unsigned char)cipher[i];
		}
		des_decryption_8(input, keyC, xorBlock, output);
		for (int i = 0; i < 8; i++) {
			plaintext = plaintext + (char)output[i];
			xorBlock[i] = input[i];
		}
		cipher = cipher.erase(0, 8);
	} while (cipher.length() != 0);

	//Depad the plaintext retrieved
	int depadding = (int)plaintext.at(plaintext.length() - 1);
	plaintext = plaintext.substr(0, plaintext.length() - depadding);

	//output the plaintext and write to file
	cout << "Plaintext retrieved: " << plaintext << endl;
	file2 << plaintext;
	cout << "plain text stored in file" << endl;

	//close both files
	file1.close();
	file2.close();
}