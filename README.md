The des_cbc.cpp file can be used on bender.cs.wright.edu to encrypt or decrypt files.

First compile the des_cbc.cpp file using the following command:
  cryptog++ des_cbc.cpp -lcryptopp -o descbc

Use the compiled file to encrypt/decrypt using the following command
  cryptoexec ./descbc <inputfile> <outputfile> <flag>
where: 
   <inputfile> represents the file containing the plaintext/ciphertext to be encrypted/decrypted
   <outputfile> represents the file to which the plaintext/ciphertext produced will be written (depending on encryption or decryption)
   <flag> is an integer value which represents whether to encrypt or decrypt the content of the inputfile. Use 0 for encrypt, and 1 for decrypt.
