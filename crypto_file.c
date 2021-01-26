#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "crypto_file.h"

//get file size
long filesize(FILE *fp)
{
	long curpos,length;
	curpos=ftell(fp);
	fseek(fp,0L,SEEK_END);
	length=ftell(fp);
	fseek(fp,curpos,SEEK_SET);
	return length;
}

int encrypt_file(uint8_t *key, char *path)
{
	FILE *frp = NULL;			//file read point
	FILE *fwp = NULL;			//file write point
	int file_size = -1;			//file size
	uint8_t *file_context = NULL;		//file context
	uint8_t *encrypt_context = NULL;	//context after encrypt
	int read_count = -1;			//how many bytes read from file
	sm4_data_t data;			//sm4 data type
	uint32_t len = -1;			//encrypt_context's length
	char crypto_file[256];			//write encrypt_context into crypto_file

	//read context from file
	frp = fopen(path, "r");
	if(frp == NULL)
	{
		printf("Cannot open %s\n", path);
		return -1;
	}
	file_size = filesize(frp);
	//printf("%s size is %d\n", path, file_size);

	file_context = (uint8_t*)malloc(sizeof(uint8_t)*file_size);
	encrypt_context = (uint8_t*)malloc(sizeof(uint8_t)*file_size+16);
	if(file_context == NULL || encrypt_context == NULL)
	{
		printf("Cannot malloc\n");
		return -1;
	}
	read_count = fread(file_context, sizeof(uint8_t), file_size, frp);
	if(read_count < 0)
	{
		printf("Cannot read %s\n", path);
		return -1;
	}
	fclose(frp);

	//sm4 encrypt
	if (sm4_data_init(&data, SM4_MODE_CBC)) {
		printf("Cannot init sm4 data\n");
		return -1;
	}
	data.key = key;
	data.iv = iv;
	sm4_encrypt_data(&data, file_context, read_count, encrypt_context, &len);
	if(len < 0)
	{
		printf("Cannot encrypt data\n");
		return -1;
	}
	//printf("%s encrypt data size is %d\n", path, len);

	//write encrypt_context into file
	strcpy(crypto_file, path);
	strcat(crypto_file, ".crypto");
	remove(crypto_file);
	fwp = fopen(crypto_file,"a");
	if(fwp == NULL)
	{
		printf("Cannot open %s\n", path);
		return -1;
	}
	if(fwrite(&file_size,sizeof(int),1,fwp) < 0)
	{
		printf("Cannot write %s\n", crypto_file);
		return -1;
	}
	if(fwrite(encrypt_context,sizeof(uint8_t),len,fwp) < 0)
	{
		printf("Cannot write %s\n", crypto_file);
		return -1;
	}
	fclose(fwp);

	//free
	remove(path);
	free(file_context);
	free(encrypt_context);
	sm4_data_exit(&data);
	return 0;
}

int decrypt_file(uint8_t *key, char *path)
{
	FILE *frp = NULL;			//file read point
	FILE *fwp = NULL;			//file write point
	int file_size = -1;			//file size
	int content_size = -1;			//original file size
	uint8_t *file_context = NULL;		//file context
	uint8_t *decrypt_context = NULL;	//context after encrypt
	int read_count = -1;			//how many bytes read from file
	sm4_data_t data;			//sm4 data type
	uint32_t len = -1;			//encrypt_context's length
	char ori_file[256];			//original file

	//read context from file
	frp = fopen(path, "r");
	if(frp == NULL)
	{
		printf("Cannot open %s\n", path);
		return -1;
	}
	file_size = filesize(frp);

	file_context = (uint8_t*)malloc(sizeof(uint8_t)*file_size);
	decrypt_context = (uint8_t*)malloc(sizeof(uint8_t)*file_size);
	if(file_context == NULL || decrypt_context == NULL)
	{
		printf("Cannot malloc\n");
		return -1;
	}
	read_count = fread(&content_size, sizeof(int), 1, frp);
	if(read_count < 0)
	{
		printf("Cannot read %s\n", path);
		return -1;
	}
	read_count = fread(decrypt_context, sizeof(uint8_t), file_size-sizeof(int), frp);
	if(read_count < 0)
	{
		printf("Cannot read %s\n", path);
		return -1;
	}
	fclose(frp);

	//sm4 decrypt
	if(sm4_data_init(&data, SM4_MODE_CBC)) {
		printf("Cannot init sm4 data\n");
		return -1;
	}
	data.key = key;
	data.iv = iv;
	sm4_decrypt_data(&data, decrypt_context, file_size, file_context, &len);
	if(len < 0)
	{
		printf("Cannot decrypt data\n");
		return -1;
	}

	//write file_context into file
	strcpy(ori_file, path);
	for(int j=1;j<8;j++)
	{
		ori_file[strlen(ori_file)-1] = '\0';
	}
	remove(ori_file);
	fwp = fopen(ori_file,"w");
	if(fwp == NULL)
	{
		printf("Cannot open %s\n", ori_file);
		return -1;
	}
	if(fwrite(file_context,sizeof(uint8_t),content_size,fwp) < 0)
	{
		printf("Cannot write %s\n", ori_file);
		return -1;
	}
	fclose(fwp);

	//free
	remove(path);
	free(file_context);
	free(decrypt_context);
	sm4_data_exit(&data);
	return 0;
}
