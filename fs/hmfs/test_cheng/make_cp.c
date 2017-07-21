/*************************************************************************
	> File Name: write.c
	> Author: 
	> Mail: 
	> Created Time: 2017年07月19日 星期三 16时34分19秒
 ************************************************************************/

#include<stdio.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>

#define WORK_DIR "/home/weiyu/mnt-hmfs/"
int main(int argc, char** argv)
{
    int fd;
    int ret;
    int i=0;
    char filename[100];

    while(1){
        sprintf(filename, "%scheckpoint_file_%d.txt", WORK_DIR, i);
        if(!access(filename, 0))
            i++;
        else{
            fd = open(filename, O_CREAT|O_WRONLY);
            break;
        }
    }
    printf("%d", fd);
    syncfs(fd);
    close(fd);
    printf("Created a new checkpoint.\n");
    return 0;
}
