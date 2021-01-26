#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "crypto_file.h"

void usage()
{
	printf("Usage: QCryptor [OPTION] [FILE|DIR]\noptions:\n\tencrypt\t\tencrypt file or dir\n\tdecrypt\t\tdecrypt file or dir\nexample:\n\t# QCryptor encrypt test.c\t(file)\n\t# QCryptor decrypt test\t\t(dir)\n");
}

int encrypt_dir(char *basePath)
{
	DIR *dir;
	struct dirent *ptr;
	char base[1000];
	char filepath[1000];

	if ((dir=opendir(basePath)) == NULL)
	{
		perror("Open dir error...");
		exit(1);
	}

	while ((ptr=readdir(dir)) != NULL)
	{
		if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0){    ///current dir OR parrent dir
			continue;
		}else if(ptr->d_type == 8){    ///file
			sprintf(filepath, "%s/%s",basePath,ptr->d_name);
			encrypt_file(key, filepath);
			printf("encrypt %s\n",filepath);
		}else if(ptr->d_type == 10){    ///link file
			printf("%s/%s will not be encrypt,because it is link file\n",basePath,ptr->d_name);
		}else if(ptr->d_type == 4){    ///dir
			memset(base,'\0',sizeof(base));
			strcpy(base,basePath);
			strcat(base,"/");
			strcat(base,ptr->d_name);
			encrypt_dir(base);
		}
	}
	closedir(dir);
	return 1;
}

int decrypt_dir(char *basePath)
{
        DIR *dir;
        struct dirent *ptr;
        char base[1000];
        char filepath[1000];

        if ((dir=opendir(basePath)) == NULL)
        {
                perror("Open dir error...");
                exit(1);
        }

        while ((ptr=readdir(dir)) != NULL)
        {
                if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0){    ///current dir OR parrent dir
                        continue;
                }else if(ptr->d_type == 8){    ///file
                        sprintf(filepath, "%s/%s",basePath,ptr->d_name);
			int suffix_p = strlen(filepath)-7;
			if(strncmp(".crypto", filepath + suffix_p, 7)){
				printf("%s will not be decrypt,because it is not .crypto\n", filepath);
				continue;
			}
                        decrypt_file(key, filepath);
                        printf("decrypt %s\n",filepath);
                }else if(ptr->d_type == 10){    ///link file
                        printf("%s/%s will not be decrypt,because it is link file\n",basePath,ptr->d_name);
                }else if(ptr->d_type == 4){    ///dir
                        memset(base,'\0',sizeof(base));
                        strcpy(base,basePath);
                        strcat(base,"/");
                        strcat(base,ptr->d_name);
                        decrypt_dir(base);
                }
        }
        closedir(dir);
        return 1;
}

int main(int argc, char **argv)
{
	struct stat file_stat;
	key = "1234567887654321";

	if(argc != 3)
	{
		usage();	
		return -1;
	}
	if(!strncmp("encrypt", argv[1], 7))
	{
		stat(argv[2], &file_stat);
		if(S_IFDIR & file_stat.st_mode)
		{
			encrypt_dir(argv[2]);
		}
		else
		{
			encrypt_file(key, argv[2]);
		}
		return 0;
	}
	if(!strncmp("decrypt", argv[1], 7))
	{
		stat(argv[2], &file_stat);
		if(S_IFDIR & file_stat.st_mode)
		{
			decrypt_dir(argv[2]);
		}
		else
		{
			decrypt_file(key, argv[2]);
		}
		return 0;
	}

	usage();
	return -1;
}
