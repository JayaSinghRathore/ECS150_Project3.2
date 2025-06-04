#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FS_SIGNATURE "ECS150FS"
#define FS_SIGNATURE_LEN 8
#define FAT_EOC 0xFFFF

struct __attribute__((packed)) superblock {
    char signature[FS_SIGNATURE_LEN];
    uint16_t total_blocks;
    uint16_t root_index;
    uint16_t data_index;
    uint16_t data_count;
    uint8_t fat_blocks;
    uint8_t padding[4079];
};

struct __attribute__((packed)) root_entry {
    char filename[FS_FILENAME_LEN];
    uint32_t size;
    uint16_t first_data_index;
    uint8_t padding[10];
};

struct fd_entry {
    int used;
    int root_index;
    size_t offset;
};

static struct superblock sb;
static uint16_t *fat = NULL;
static struct root_entry root[FS_FILE_MAX_COUNT];
static struct fd_entry fd_table[FS_OPEN_MAX_COUNT];
static int fs_mounted = 0;

// Helper: find root entry by filename
static int find_root(const char *filename) {
    for (int i = 0; i < FS_FILE_MAX_COUNT; ++i)
        if (strncmp(root[i].filename, filename, FS_FILENAME_LEN) == 0)
            return i;
    return -1;
}

// Helper: find free root entry
static int find_free_root(void) {
    for (int i = 0; i < FS_FILE_MAX_COUNT; ++i)
        if (root[i].filename[0] == '\0')
            return i;
    return -1;
}

// Helper: find free FAT entry (first-fit, skip 0)
static uint16_t find_free_fat(void) {
    for (uint16_t i = 1; i <= sb.data_count; ++i)
        if (fat[i] == 0)
            return i;
    return 0;
}

// Helper: find free fd entry
static int find_free_fd(void) {
    for (int i = 0; i < FS_OPEN_MAX_COUNT; ++i)
        if (!fd_table[i].used)
            return i;
    return -1;
}

int fs_mount(const char *diskname)
{
    if (fs_mounted)
        return -1;
    if (block_disk_open(diskname) < 0)
        return -1;
    uint8_t buf[BLOCK_SIZE];
    if (block_read(0, buf) < 0) {
        block_disk_close();
        return -1;
    }
    memcpy(&sb, buf, sizeof(struct superblock));
    if (memcmp(sb.signature, FS_SIGNATURE, FS_SIGNATURE_LEN) != 0) {
        block_disk_close();
        return -1;
    }
    if (sb.total_blocks != block_disk_count()) {
        block_disk_close();
        return -1;
    }
    size_t fat_entries = sb.data_count + 1;
    fat = malloc(fat_entries * sizeof(uint16_t));
    if (!fat) {
        block_disk_close();
        return -1;
    }
    for (size_t i = 0; i < sb.fat_blocks; ++i) {
        if (block_read(1 + i, ((uint8_t*)fat) + i * BLOCK_SIZE) < 0) {
            free(fat);
            fat = NULL;
            block_disk_close();
            return -1;
        }
    }
    if (block_read(sb.root_index, root) < 0) {
        free(fat);
        fat = NULL;
        block_disk_close();
        return -1;
    }
    memset(fd_table, 0, sizeof(fd_table));
    fs_mounted = 1;
    return 0;
}

int fs_umount(void)
{
    if (!fs_mounted)
        return -1;
    for (int i = 0; i < FS_OPEN_MAX_COUNT; ++i)
        if (fd_table[i].used)
            return -1;
    for (size_t i = 0; i < sb.fat_blocks; ++i) {
        if (block_write(1 + i, ((uint8_t*)fat) + i * BLOCK_SIZE) < 0)
            return -1;
    }
    if (block_write(sb.root_index, root) < 0)
        return -1;
    free(fat);
    fat = NULL;
    fs_mounted = 0;
    if (block_disk_close() < 0)
        return -1;
    return 0;
}

int fs_info(void)
{
    // Defensive: ensure the file system is mounted and FAT is allocated
    if (!fs_mounted || fat == NULL)
        return -1;

    // Print required file system information in the exact expected format
    printf("FS Info:\n");
    printf("total_blk_count=%u\n", sb.total_blocks);
    printf("fat_blk_count=%u\n", sb.fat_blocks);
    printf("rdir_blk=%u\n", sb.root_index);
    printf("data_blk=%u\n", sb.data_index);
    printf("data_blk_count=%u\n", sb.data_count);

    // Count free FAT entries (entries with value 0, skipping index 0)
    size_t free_fat = 0;
for (size_t i = 1; i < sb.data_count; ++i)
        if (fat[i] == 0)
            free_fat++;
    printf("fat_free_ratio=%zu/%u\n", free_fat, sb.data_count);

    // Count free root directory entries (filename[0] == '\0')
    size_t free_root = 0;
    for (size_t i = 0; i < FS_FILE_MAX_COUNT; ++i)
        if (root[i].filename[0] == '\0')
            free_root++;
    printf("rdir_free_ratio=%zu/%d\n", free_root, FS_FILE_MAX_COUNT);

    return 0;
}

int fs_create(const char *filename)
{
    if (!fs_mounted || !filename)
        return -1;
    size_t len = strnlen(filename, FS_FILENAME_LEN);
    if (len == 0 || len >= FS_FILENAME_LEN)
        return -1;
    if (find_root(filename) != -1)
        return -1;
    int idx = find_free_root();
    if (idx == -1)
        return -1;
    memset(&root[idx], 0, sizeof(struct root_entry));
    strncpy(root[idx].filename, filename, FS_FILENAME_LEN - 1);
    root[idx].filename[FS_FILENAME_LEN - 1] = '\0';
    root[idx].size = 0;
    root[idx].first_data_index = FAT_EOC;
    return 0;
}

int fs_delete(const char *filename)
{
    if (!fs_mounted || !filename)
        return -1;
    int idx = find_root(filename);
    if (idx == -1)
        return -1;
    for (int i = 0; i < FS_OPEN_MAX_COUNT; ++i)
        if (fd_table[i].used && fd_table[i].root_index == idx)
            return -1;
    uint16_t b = root[idx].first_data_index;
    while (b != FAT_EOC && b != 0) {
        uint16_t next = fat[b];
        fat[b] = 0;
        b = next;
    }
    memset(&root[idx], 0, sizeof(struct root_entry));
    return 0;
}

int fs_ls(void)
{
    if (!fs_mounted)
        return -1;
    printf("FS Ls:\n");
    for (int i = 0; i < FS_FILE_MAX_COUNT; ++i) {
        if (root[i].filename[0] != '\0') {
            printf("file: %s, size: %u, data_blk: %u\n",
                   root[i].filename, root[i].size, root[i].first_data_index);
        }
    }
    return 0;
}

int fs_open(const char *filename)
{
    if (!fs_mounted || !filename)
        return -1;
    int root_idx = find_root(filename);
    if (root_idx == -1)
        return -1;
    int fd = find_free_fd();
    if (fd == -1)
        return -1;
    fd_table[fd].used = 1;
    fd_table[fd].root_index = root_idx;
    fd_table[fd].offset = 0;
    return fd;
}

int fs_close(int fd)
{
    if (!fs_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].used)
        return -1;
    fd_table[fd].used = 0;
    return 0;
}

int fs_stat(int fd)
{
    if (!fs_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].used)
        return -1;
    return root[fd_table[fd].root_index].size;
}

int fs_lseek(int fd, size_t offset)
{
    if (!fs_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].used)
        return -1;
    if (offset > root[fd_table[fd].root_index].size)
        return -1;
    fd_table[fd].offset = offset;
    return 0;
}

int fs_read(int fd, void *buf, size_t count)
{
    if (!fs_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].used || !buf)
        return -1;
    struct root_entry *re = &root[fd_table[fd].root_index];
    if (fd_table[fd].offset >= re->size)
        return 0;
    if (count > re->size - fd_table[fd].offset)
        count = re->size - fd_table[fd].offset;
    size_t bytes_read = 0;
    size_t offset = fd_table[fd].offset;
    uint16_t block_idx = re->first_data_index;
    size_t skip = offset / BLOCK_SIZE;
    for (size_t i = 0; i < skip && block_idx != FAT_EOC; ++i)
        block_idx = fat[block_idx];
    while (bytes_read < count && block_idx != FAT_EOC) {
        uint8_t bounce[BLOCK_SIZE];
        if (block_read(sb.data_index + block_idx, bounce) < 0)
            break;
        size_t block_off = offset % BLOCK_SIZE;
        size_t to_copy = BLOCK_SIZE - block_off;
        if (to_copy > count - bytes_read)
            to_copy = count - bytes_read;
        memcpy((uint8_t*)buf + bytes_read, bounce + block_off, to_copy);
        bytes_read += to_copy;
        offset += to_copy;
        block_idx = fat[block_idx];
    }
    fd_table[fd].offset += bytes_read;
    return bytes_read;
}

int fs_write(int fd, void *buf, size_t count)
{
    if (!fs_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].used || !buf)
        return -1;
    struct root_entry *re = &root[fd_table[fd].root_index];
    size_t offset = fd_table[fd].offset;
    size_t bytes_written = 0;

    // Allocate first block if needed
    if (re->first_data_index == FAT_EOC && count > 0) {
        uint16_t new_block = find_free_fat();
        if (new_block == 0)
            return 0;
        fat[new_block] = FAT_EOC;
        re->first_data_index = new_block;
    }

    // Find the block and offset to start writing
    uint16_t block_idx = re->first_data_index;
    size_t skip = offset / BLOCK_SIZE;
    uint16_t prev = FAT_EOC;
    for (size_t i = 0; i < skip; ++i) {
        if (block_idx == FAT_EOC) {
            uint16_t new_block = find_free_fat();
            if (new_block == 0)
                return bytes_written;
            fat[new_block] = FAT_EOC;
            fat[prev] = new_block;
            block_idx = new_block;
        }
        prev = block_idx;
        block_idx = fat[block_idx];
    }

    while (bytes_written < count) {
        if (block_idx == FAT_EOC) {
            uint16_t new_block = find_free_fat();
            if (new_block == 0)
                break;
            fat[new_block] = FAT_EOC;
            fat[prev] = new_block;
            block_idx = new_block;
        }
        uint8_t bounce[BLOCK_SIZE];
        size_t block_off = (offset + bytes_written) % BLOCK_SIZE;
        if (block_off != 0 || (count - bytes_written) < BLOCK_SIZE) {
            block_read(sb.data_index + block_idx, bounce);
        } else {
            memset(bounce, 0, BLOCK_SIZE);
        }
        size_t to_copy = BLOCK_SIZE - block_off;
        if (to_copy > count - bytes_written)
            to_copy = count - bytes_written;
        memcpy(bounce + block_off, (uint8_t*)buf + bytes_written, to_copy);
        block_write(sb.data_index + block_idx, bounce);
        bytes_written += to_copy;
        prev = block_idx;
        block_idx = fat[block_idx];
    }
    fd_table[fd].offset += bytes_written;
    if (fd_table[fd].offset > re->size)
        re->size = fd_table[fd].offset;
    return bytes_written;
}
