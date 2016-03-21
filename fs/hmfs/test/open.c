#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    FILE* fps[2048];
    char filename[100];
    for (int i = 0; i < 2048; i++) {
        sprintf(filename, "/home/wgtdkp/mount_hmfs/orphan_%d.txt", i);
        printf("%s\n", filename);
        fps[i] = fopen(filename, "r");
        if (!fps[i])
            printf("error!\n");
    }
    while (1) {}
    return 0;
}