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
    int ret = 0;
    int t=0;
    int i=0;
    int total=0;
    char ch;
    char lastch;
    char board;
    char buf[1024];
    FILE *fp;
    fp = fopen(argv[1],"r");
    if (argc >= 3) start = atoi(argv[2]);
    ret = fseek(fp, start*1024, SEEK_SET);
    if(ret!=0) {printf("fseek() unsuccessful!\n"); return -1;}
    printf("Content:\n--------\n");
    
    fgets(buf,1025,fp);
    ch = buf[0];
    board = ch;
    t = ch-'A';
    while (t>0) {
        printf(" ");
        t--;
    }
    // printf("ch:%c\nb:%c\n",buf[0],board);
    while (ch!=lastch) {
        // printf("%c",ch);
        for (i=0;i<1023;++i) {
            if (buf[i]!=board) {
                goto wrong;
            }
        }
        printf("%c",board);
        if (board=='Z') printf("\n");
        total++;
        goto next;
wrong:
        printf("?");
next:
        lastch = ch;
        fgets(buf,1025,fp);
        ch = buf[0];
        board = ch;
    }
    printf("\n--------\n");
    printf("Total: %d\n",total);
    fclose(fp);
    return 0;
}