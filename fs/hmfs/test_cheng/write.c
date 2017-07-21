/*************************************************************************
	> File Name: write.c
	> Author: 
	> Mail: 
	> Created Time: 2017年07月19日 星期三 16时34分19秒
 ************************************************************************/

#include<stdio.h>
#include<string.h>

#define FILE_NUM 200
#define WORK_DIR "/home/weiyu/mnt-hmfs/"
int main(int argc, char**argv)
{
    FILE *fps[FILE_NUM];
    int i=0;
    FILE *fp1;
    char buf[1024];
    char filename[128];

    fp1 = fopen(argv[1], "r");
    if(!fp1){
        printf("error reading source file!\n");
        return -1;
    }
    
    for(i=0; i<FILE_NUM; i++ ){
        sprintf(filename, "%stest_file_%d.txt",WORK_DIR, i);
        fps[i] = fopen(filename, "w");
        if (!fps[i])
            printf("error!\n");
        while(fgets(buf, sizeof(buf), fp1)!=NULL){
            fputs(buf, fps[i]);
        }
        fclose(fps[i]);
        rewind(fp1);
    }

    fclose(fp1);
    printf("All files are written!\n");
    return 0;
}
