#include <stdio.h>
#include <string.h>

//  argv[1] = address of the file
//  argv[2] = block number

int main(int argc, char* argv[]){
    int start = 0;
    int length = 256;
    int ret = 0;
    int i;
    char buf[256];
    FILE *fp;
    fp = fopen(argv[1],"r");
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