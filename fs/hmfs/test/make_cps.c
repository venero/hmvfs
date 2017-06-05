#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>

#define BLK_SIZE 4096
#define FILE_BLKS 1024
#define NR_MODIFY_BLKS 256
#define NR_CPS 100

#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

void fill_buf(char* buf, size_t n) {
    char c = (rand() % 2 == 0 ? 'a' : 'A') + rand() % 26;
    memset(buf, c, n);
}

int create_file(char* filename) {
    int fd;
    if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE)) < 0) {
        perror("Create File");
        return 1;
    }
    int i;
    char buffer[BLK_SIZE];
    for (i = 0; i < FILE_BLKS; ++i) {
        fill_buf(buffer, BLK_SIZE);
        if (write(fd, buffer, BLK_SIZE) != BLK_SIZE) {
            perror("Write");
            return 1;
        }
    }
    close(fd);
    return 0;
}

int modify_file(char* filename) {
    int fd;
    if ((fd = open(filename, O_WRONLY, FILE_MODE)) < 0) {
        perror("Open File");
        return 1;
    }
    int i;
    off_t off_set;
    char buffer[BLK_SIZE];
    for (i = 0; i < NR_MODIFY_BLKS; ++i) {
        off_set = (rand() % FILE_BLKS) * BLK_SIZE;
        lseek(fd, off_set, SEEK_SET);
        fill_buf(buffer, BLK_SIZE);
        if (write(fd, buffer, BLK_SIZE) != BLK_SIZE) {
            perror("Write");
            return 1;
        }
    }
    close(fd);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage : %s FILE_NAME\n", argv[0]);
        return 1;
    }
    srand((unsigned)time(NULL)); 
    if(create_file(argv[1])) return 1;
    int i;
    for (i = 0; i < NR_CPS; ++i) {
        if (modify_file(argv[1])) return 1;
        sync();
    }
    printf("\n");
    return 0;
}