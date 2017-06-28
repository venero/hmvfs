#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#define FILE_NAME "testfile"
#define FILE_MODE S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
#define FILE_SIZE 4096

int create_file() {
    int fd = open(FILE_NAME, O_RDWR | O_CREAT, FILE_MODE);
    char buf[FILE_SIZE];
    memset(buf, 'x', FILE_SIZE);
    write(fd, buf, FILE_SIZE);
    close(fd);
    return 1;
}

int main() {
    create_file();
    int fd = open(FILE_NAME, O_RDWR);
    char *addr = mmap(0, FILE_SIZE, PROT_WRITE|PROT_READ, MAP_PRIVATE, fd, 0);
    memset(addr, 'a', FILE_SIZE/2);
    lseek(fd, FILE_SIZE/2, SEEK_SET);
    char buf[FILE_SIZE / 2];
    memset(buf, 'b', FILE_SIZE / 2);
    write(fd, buf, FILE_SIZE / 2);
    close(fd);
    return 0;
}