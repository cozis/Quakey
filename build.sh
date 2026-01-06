gcc -o demo_client     demo/client.c demo/server.c demo/main.c demo/utils.c -DMAIN_CLIENT -Wall -Wextra -Iinclude -ggdb -O0
gcc -o demo_server     demo/client.c demo/server.c demo/main.c demo/utils.c -DMAIN_SERVER -Wall -Wextra -Iinclude -ggdb -O0
gcc -o demo_simulation src/libc.c src/lfs.c src/lfs_util.c src/malloc.c src/rpmalloc.c src/quakey.c demo/client.c demo/server.c demo/main.c demo/utils.c -DMAIN_SIMULATION -Wall -Wextra -Iinclude -nostdlib -ggdb -O0
