#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/*
 *  Usage: ./a.out file 5 0
 *  file: "AAA...AAA\nBBB...BBB\nCCC...CCC\nDDD...DDD\nEEE...EEE\n" with 1023 copies of each character
 *  thus, file size = 5*1024 = 5KB in this case
 *  argv[1] = address of the file
 *  argv[2] = size of the file in KB, default = 4
 */

int main(int argc, char* argv[]){
    int filesize = 4;
    int i=0;
    int count=0;
    char c[2];
    c[0] = 'A';
    c[1] = '\0';
    char cc[1023];
    if (argc == 4) c[0]+=atoi(argv[3]);    
    if (argc >= 3) filesize = atoi(argv[2]);
    FILE *fp;
    fp = fopen(argv[1],"a");
    fclose(fp);
    fp = fopen(argv[1],"r+");
    while (count<filesize) {
        cc[0]='\0';
        for (i=0;i<1023;++i) strcat(cc,c);
        //	printf("%s",cc);
        fputs(cc, fp);
        fputc('\n', fp);
        if (c[0]=='Z') c[0]='A'; else c[0]=c[0]+1;
        count++;
    }
    fclose(fp);
    return 0;
}
