#ifndef DISK_INCLUDED
#define DISK_INCLUDED

#include "3p/lfs.h"

typedef struct {
    lfs_file_t file;
} DiskOpenFile;

typedef struct {
    lfs_dir_t dir;
} DiskOpenDir;

typedef struct {

    int   size;
    char *data;

    lfs_t lfs;
    struct lfs_config lfs_cfg;
} Disk;

int  disk_init(Disk *disk, int size);
void disk_free(Disk *disk);

void disk_close_file(DiskOpenFile *file);
void disk_close_dir(DiskOpenDir *dir);

#endif // DISK_INCLUDED