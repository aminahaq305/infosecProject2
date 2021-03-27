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

//AES ENCODE GIVEN
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

//AES DECODE GIVEN
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

//Calculate the percentage of the recovered text alphabets that are in valid english
bool percentageCalc(string plain) {
	//if the recovered plaintext is empty return false
	if (plain.length() == 0) {
		return false;
	}
	int percent = 0;
	//for each character in the recovered plaintext
	//if the character is valid english, increment the precentage
	for (int i = 0; i < plain.size(); i++) {
		int x = plain.at(i);
		if ((x >= 48 && x <= 59) || (x >= 44 && x <= 46) ||
			(x >= 39 && x <= 41) || (x >= 32 && x <= 34) || (x == 10) || (x == 63) ||
			(x >= 65 && x <= 90) || (x >= 97 && x <= 122)) {
			percent = percent + 1;
		}
	}
	percent = (percent / (plain.length())) * 100;
	//if the percentage of valid characters is greater than 90, return true
	if (percent >= 90) {
		return true;
	}
	return false;
}

int main()
{
	//----------START OF VARIABLE DECLARATION-------------
	string plaintext = "Hello"; //simple plaintext that I am using for testing purpose
	string ciphertext = ""; //variable to hold the ciphertext produced after encrypting above plaintext
	string recoveredtext = ""; //variable to hold the text recovered for each brute force iteration
	byte givenkey[AES::DEFAULT_KEYLENGTH + 1] = "000ax7qfkp3mbv9w"; //the key I will use
	////try it with "000ax7qfkp3mbv9w" and it takes a split second, anything relatively larger takes near infinite time

	byte guessedkey[AES::DEFAULT_KEYLENGTH + 1] = "0000x7qfkp3mbv9w"; //the key that will be brute force searched
	string guessKeypref = "wxyz"; //the first four characters of the key
	string guessKeysuff = "x7qfkp3mbv9w"; //the part of the key that is given
	string candidate = ""; //this will hold the key that is identified as the correct one
	string combinations = "0123456789abcdefghijklmnopqrstuvwxyz"; //all possible 36 combinations for the key characters
	bool end = false; //this keeps track of whether the desired key is found or not

	//---------DECRYPTING-------------
	ciphertext = ciphertext + aes_encode(plaintext, givenkey); //
	cout << ciphertext << endl;

	//------START OF BRUTEFORCE----------
	for (int i = 0; i < 36 && !end; i++) { //this for loop works using the combinations string, so 0000.....zzzz
		for (int j = 0; j < 36 && !end; j++) {
			for (int k = 0; k < 36 && !end; k++) {
				for (int l = 0; l < 36 && !end; l++) {
					//update the prefix
					guessKeypref[0] = combinations[i]; 
					guessKeypref[1] = combinations[j];
					guessKeypref[2] = combinations[k];
					guessKeypref[3] = combinations[l];
					//update the first four bytes of the key that will be used for bruteforce decryption
					for (int i = 0; i < 4; i++) {
						guessedkey[i] = guessKeypref[i];
					}
					//store the recovered text in a variable
					recoveredtext = aes_decode(ciphertext, guessedkey);
					//if the percentage is more than 90, output the key and the recovered text
					if (percentageCalc(recoveredtext)) {
						candidate = guessKeypref + guessKeysuff;
						cout << "Key: " << candidate << endl;
						cout << "Recovered text: " << recoveredtext << endl;
						end = true;
					}
				}
			}
		}
	}
}
