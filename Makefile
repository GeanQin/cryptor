all:
	gcc sm4.c crypto_file.c main.c -g -o QCryptor -lssl -lcrypto

clean:
	rm -rf QCryptor test/*.crypto
