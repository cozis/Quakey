#include "disk.h"

static int block_device_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
    Disk *disk = c->context;

    // TODO
}

static int block_device_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
{
    Disk *disk = c->context;

    // TODO
}

static int block_device_erase(const struct lfs_config *c, lfs_block_t block)
{
    Disk *disk = c->context;

    // TODO
}

static int block_device_sync(const struct lfs_config *c)
{
    Disk *disk = c->context;

    // TODO
}

int disk_init(Disk *disk, int size)
{
    disk->size = size;
    disk->data = malloc(size);
    if (disk->data == NULL)
        return -1;

    // Zero out memory to make sure operations are deterministic
    memset(disk->data, 0, disk->size);

    disk->lfs_cfg = (struct lfs_config) {

        .context = disk,

        // block device operations
        .read  = block_device_read,
        .prog  = block_device_prog,
        .erase = block_device_erase,
        .sync  = block_device_sync,

        // block device configuration
        .read_size = 16,
        .prog_size = 16,
        .block_size = 4096,
        .block_count = 128,
        .cache_size = 16,
        .lookahead_size = 16,
        .block_cycles = 500,
    };

    int err = lfs_mount(&disk->lfs, &disk->lfs_cfg);
    if (err) {
        lfs_format(&disk->lfs, &disk->lfs_cfg); // TODO: can this fail?
        err = lfs_mount(&disk->lfs, &disk->lfs_cfg);
        if (err) {
            free(disk->data);
            return -1;
        }
    }

    return 0;
}

void disk_free(Disk *disk)
{
    lfs_unmount(&disk->lfs);
    free(disk->data);
}

int disk_open_file(Disk *disk, DiskOpenFile *file)
{
    // TODO
}

int disk_open_dir(Disk *disk, DiskOpenDir *dir)
{
    // TODO
}

void disk_close_file(DiskOpenFile *file)
{
    // TODO
}

void disk_close_dir(DiskOpenDir handle)
{
    // TODO
}
