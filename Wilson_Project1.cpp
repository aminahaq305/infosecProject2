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

void des_encryption_8(unsigned char *input, unsigned char *key,
		                unsigned char *xorBlock, unsigned char *output)
{

	    DESEncryption desEncryptor;
	    desEncryptor.SetKey(key,8);
	    desEncryptor.ProcessAndXorBlock(input,xorBlock,output);
}
	
void des_decryption_8(unsigned char *input, unsigned char *key,
		                unsigned char *xorBlock, unsigned char *output)
{

	    DESDecryption desDecryptor;
	    desDecryptor.SetKey(key,8);
	    desDecryptor.ProcessAndXorBlock(input,xorBlock,output);
}

int main(int argc, char * argv[])
{
	fstream file1;
	fstream file2;
	unsigned char keyC[DES::DEFAULT_KEYLENGTH];
	unsigned char xorBlock[DES::BLOCKSIZE];
	unsigned char input[DES::BLOCKSIZE];
	unsigned char output[DES::BLOCKSIZE];
	byte key[DES::DEFAULT_KEYLENGTH] = {0x14, 0x0b, 0xb2, 0x2a, 0xb4, 0x06, 0xb6, 0x74};
	byte iv[DES::BLOCKSIZE] = {0x4c, 0xa0, 0x0f, 0xd6, 0xdb, 0xf1, 0xfb, 0x28};
	string cipher = "";

	if(argc!=4)
	{
		cout<<"usage:Wilson_Project1.cpp infile outfile flag[0 for encode, 1 for decode]"<<endl;
	}
	file1.open(argv[1],ios::in);
	file2.open(argv[2],ios::out);
	//reading
	stringstream buffer;  
	buffer << file1.rdbuf();  
	string plain(buffer.str());  
	
	// Pad the plaintext
	int paddedsize = 1;
	if (plain.length() % 8 != 0) {
	  paddedsize = 8 - (plain.length() % 8); 
	}
 	for (int i = 0; i < paddedsize; i++){
    	  plain = plain + (char)paddedsize; 
  	}

	//Convert key to char, set xorBlock to iv, and setup the first input
	for (int i = 0; i < 8; i++){
		keyC[i] = (unsigned char)key[i];
		xorBlock[i] = (unsigned char)iv[i];
		input[i] = (unsigned char)plain[i];
	}

	//encode the first block
	des_encryption_8(input, keyC,xorBlock, output);
	for (int i = 0; i < 8; i++){
		cipher = cipher + (char)output[i];
		input[i] = output[i];
	}
	file2 << cipher;
	cipher = "";

	des_decryption_8(input, keyC, xorBlock, output);
	for (int i = 0; i < 8; i++){
		cipher = cipher + (char)output[i];
	}

	cout << cipher << endl;

	cout<<"cipher text stored in:"<<argv[2]<<endl;
	
	file1.close();
	file2.close();	
}	
