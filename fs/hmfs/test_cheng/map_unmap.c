/*************************************************************************
	> File Name: open_close.c
	> Author: 
	> Mail: 
	> Created Time: 2017年07月19日 星期三 15时18分26秒
 ************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<sys/stat.h>

#define WORK_DIR "/home/weiyu/mnt-hmfs/"
#define FILE_NUM 200

int main()
{
    FILE* fps[FILE_NUM];
    struct stat file_stat[FILE_NUM];
    char filename[100];
    void * start_fp[FILE_NUM];
    char input[100];
    int i;

    for (i = 0; i < FILE_NUM; i++) {
        sprintf(filename, "%stest_file_%d.txt",WORK_DIR, i);
        printf("%s\n", filename);
        fps[i] = fopen(filename, "rt+");
        if (!fps[i]){
            printf("error!\n");
            return -1;
        }
        if(fstat(fileno(fps[i]), &file_stat[i])<0){
            printf("fstat wrong!\n");
            return -1;
        }
        if((start_fp[i] = mmap(NULL, file_stat[i].st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fileno(fps[i]), 0))==MAP_FAILED){
            printf("mmap wrong!\n");
            return -1;
        }
        printf("%.128s", (char*) start_fp[i]);
    }
    
    printf("Input \"unmap\" to unmap mapped files.\n");
    while(scanf("%s", input)!=EOF){
        if(!strcmp(input, "unmap"))
            break;
    }

    for ( i = 0; i < FILE_NUM; i++) {
        munmap(start_fp[i], file_stat[i].st_size);
    }
    printf("Files unmapped!.\n");
    
    return 0;
}
