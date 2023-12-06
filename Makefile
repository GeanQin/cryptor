all:
	gcc test.c sm4.c base64.c rsa.c -lcrypto -lssl -o qcryptor

clean:
	rm -rf qcryptor
