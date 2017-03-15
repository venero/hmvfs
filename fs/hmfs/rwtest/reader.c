#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 *  Usage: ./a.out file 2 1
 *  file: "1234"
 *  output: "3"
 *  argv[1] = address of the file
 *  argv[2] = start byte
 *  argv[3] = length
 */

int main(int argc, char* argv[]){
    int start = 0;
    int length = 256;
    int ret = 0;
    int i;
    char buf[256];
    char sy[100];
    FILE *fp;
    fp = fopen(argv[1],"r");
    sy[0]='\0';
    strcat(sy,"md5sum ");
    strcat(sy,argv[1]);
    if (argc == 2) {
        system(sy); 
        return 0;
    }
    if (argc >= 3) start = atoi(argv[2]);
    if (argc >= 4) length = atoi(argv[3]);
    ret = fseek(fp, start, SEEK_SET);
    if(ret!=0) {printf("fseek() unsuccessful!\n"); return -1;}
    for (i=0;i<length;++i){
        buf[i] = fgetc(fp);
    }
    printf("Content:\n--------\n");
    for (i=0;i<length;++i){
        printf("%c",buf[i]);
    }
    printf("\n--------\n");
    fclose(fp);
    return 0;
}