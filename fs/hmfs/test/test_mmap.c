#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

#define BLK_SIZE 4096
#define FILE_BLKS 2
#define NR_MODIFY_BLKS 256
#define NR_CPS 100

#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define MMAP_MODE MAP_SHARED

void fill_buf(char* buf, size_t n, char c) {
    //char c = (rand() % 2 == 0 ? 'a' : 'A') + rand() % 26;
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
        fill_buf(buffer, BLK_SIZE, 'x');
        if (write(fd, buffer, BLK_SIZE) != BLK_SIZE) {
            perror("Write");
            close(fd);
            return 1;
        }
    }
    close(fd);
    return 0;
}

int mmap_file(char* filename) {
    int fd;
    if ((fd = open(filename, O_RDWR)) < 0) {
        perror("open file");
        return 1;
    }
    char *mapped_area;
    if ((mapped_area = mmap(NULL, BLK_SIZE * FILE_BLKS, PROT_READ | PROT_WRITE, MMAP_MODE, fd, 0)) == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    fill_buf(mapped_area, BLK_SIZE, 'a');
    fill_buf(mapped_area + BLK_SIZE, BLK_SIZE, 'a');
    printf("before sync()\n");
    sync();
    printf("after sync()\n");
    fill_buf(mapped_area, BLK_SIZE, 'b');
    fill_buf(mapped_area + BLK_SIZE, BLK_SIZE, 'b');
    munmap(mapped_area, BLK_SIZE * FILE_BLKS);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("please specify the file name!\n");
        return 1;
    }
    if (create_file(argv[1])) return 1;
    if (mmap_file(argv[1])) return 1;
    return 0;
}