/*************************************************************************
	> File Name: open_close.c
	> Author: 
	> Mail: 
	> Created Time: 2017年07月19日 星期三 15时18分26秒
 ************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define WORK_DIR "/home/weiyu/mnt-hmfs/"
#define FILE_NUM 200

int main()
{
    FILE* fps[FILE_NUM];
    char filename[100];
    char lsof_cmd[100];
    char input[100];
    for (int i = 0; i < FILE_NUM; i++) {
        sprintf(filename, "%stest_file_%d.txt",WORK_DIR, i);
        printf("%s\n", filename);
        fps[i] = fopen(filename, "r");
        if (!fps[i])
            printf("error!\n");
    }
    printf("Run lsof command:\n");
    sprintf(lsof_cmd, "lsof %s | grep open_clos", WORK_DIR);
    system(lsof_cmd);
    
    printf("Input \"close\" to close opened files.\n");
    while(scanf("%s", input)!=EOF){
        if(!strcmp(input, "close"))
            break;
    }

    for (int i = 0; i < FILE_NUM; i++) {
        fclose(fps[i]);
    }

    printf("Run lsof command:\n");
    sprintf(lsof_cmd, "lsof %s | grep open_clos", WORK_DIR);
    system(lsof_cmd);
    
    return 0;
}
