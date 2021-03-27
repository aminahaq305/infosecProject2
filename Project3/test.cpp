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


string aes_encode(string& plain, byte key[])
{
	string cipher;
	try {
		ECB_Mode<AES>::Encryption enc;
		enc.SetKey(key, AES::DEFAULT_KEYLENGTH);
		StringSource s(plain, true, new StreamTransformationFilter(enc, new StringSink(cipher)));
	}
	catch (const CryptoPP::Exception& e)
	{
	}
	return cipher;
}

string aes_decode(string& cipher, byte key[])
{
	string plain;
	try {
		ECB_Mode< AES >::Decryption dec;
		dec.SetKey(key, AES::DEFAULT_KEYLENGTH);
		StringSource s(cipher, true, new StreamTransformationFilter(dec, new StringSink(plain)));
	}
	catch (const CryptoPP::Exception& e) {
	}
	return plain;
}

bool percentageCalc(string plain) {
	if (plain.length() == 0) {
		return false;
	}
	int percent = 0;
	for (int i = 0; i < plain.size(); i++) {
		int x = plain.at(i);
		if ((x >= 48 && x <= 59) || (x >= 44 && x <= 46) ||
			(x >= 39 && x <= 41) || (x >= 32 && x <= 34) || (x == 10) || (x == 63) ||
			(x >= 65 && x <= 90) || (x >= 97 && x <= 122)) {
			percent = percent + 1;
		}
	}
	percent = (percent / (plain.length())) * 100;
	if (percent >= 90) {
		return true;
	}
	return false;
}

int main()
{
	string plaintext = "Hello";
	string ciphertext = "";
	string recoveredtext = "";
	byte givenkey[AES::DEFAULT_KEYLENGTH + 1] = "aaaax7qfkp3mbv9w";
	byte guessedkey[AES::DEFAULT_KEYLENGTH + 1] = "0000x7qfkp3mbv9w";
	string guessKeypref = "wxyz";
	string guessKeysuff = "x7qfkp3mbv9w";
	string guessKey = "";
	string candidate = "";
	string combinations = "0123456789abcdefghijklmnopqrstuvwxyz";
	bool end = false;
	ciphertext = ciphertext + aes_encode(plaintext, givenkey);
	cout << ciphertext << endl;
	for (int i = 0; i < 36 && !end; i++) {
		for (int j = 0; j < 36 && !end; j++) {
			for (int k = 0; k < 36 && !end; k++) {
				for (int l = 0; l < 36 && !end; l++) {
					guessKeypref[0] = combinations[i];
					guessKeypref[1] = combinations[j];
					guessKeypref[2] = combinations[k];
					guessKeypref[3] = combinations[l];
					for (int i = 0; i < 4; i++) {
						guessedkey[i] = guessKeypref[i];
					}
					recoveredtext = aes_decode(ciphertext, guessedkey);
					if (percentageCalc(recoveredtext)) {
						candidate = guessKeypref + guessKeysuff;
					}
					if (candidate.length() > 1) {
						cout << "Key: " << candidate << endl;
						cout << "Recovered text: " << recoveredtext << endl;
						end = true;
					}
				}
			}
		}
	}
}