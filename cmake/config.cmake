include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckCSourceCompiles)

# Check for mmap() support, required for HAVE_MPOOL.
#
# checks for private fixed mappings, we don't need fixed mappings,
# so check only wether private mappings work.
check_include_file(sys/mman.h HAVE_SYS_MMAN_H)
if(MMAP_FOR_CROSSCOMPILING)
    set(HAVE_MMAP 1)
else()
    check_c_source_compiles(
        "
            #include <unistd.h>
            #include <stdlib.h>
            #include <sys/mman.h>
            #ifdef HAVE_SYS_TYPES_H
            #include <sys/types.h>
            #endif
            #ifdef HAVE_SYS_STAT_H
            #include <sys/stat.h>
            #endif
            #include <fcntl.h>
            int main(void)
            {
                char *data, *data2, *data3;
                size_t i, datasize = 1024;
                int fd;

                /* First, make a file with some known garbage in it. */
                data = (char*) malloc(datasize);
                if(!data)
                    return 1;
                for(i=0;i<datasize;i++)
                    *(data + i) = rand();
                umask(0);
                fd = creat(\"conftest.mmap\", 0600);
                if(fd < 0)
                    return 1;
                if(write (fd, data, datasize) != datasize)
                    return 1;
                close(fd);
                fd = open(\"conftest.mmap\", O_RDWR);
                if (fd < 0)
                    return 1;
                /* Next, try to mmap the file at a fixed address which already has
                something else allocated at it.  If we can, also make sure that
                we see the same garbage.  */
                data2 = mmap(NULL, sizeof(data), PROT_READ | PROT_WRITE,
                    MAP_PRIVATE, fd, 0L);
                if(data2 == MAP_FAILED)
                    return 2;
                for(i=0;i<sizeof(data);i++)
                    if(*(data + i) != *(data2+ i))
                        return 3;
                /* Finally, make sure that changes to the mapped area do not
                        percolate back to the file as seen by read().  (This is a bug on
                        some variants of i386 svr4.0.)  */
                for (i = 0; i < datasize; ++i)
                    *(data2 + i) = *(data2 + i) + 1;
                data3 = (char*) malloc(datasize);
                if(!data3)
                    return 1;
                if(read (fd, data3, datasize) != datasize)
                    return 1;
                for(i=0;i<sizeof(data);i++)
                    if(*(data + i) != *(data3 + i))
                        return 3;
                close(fd);
                return 0;
            }
        "
        HAVE_MMAP
    )
endif()

# Check the flag name for the ANONYMOUS_MAP feature.
check_c_source_compiles(
    "
        #include <sys/mman.h>
        int main(void)
        {
            mmap((void *)0, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            return 0;
        }
    "
    HAVE_MMAP_MAP_ANONYMOUS
)
if(HAVE_MMAP_MAP_ANONYMOUS)
    set(ANONYMOUS_MAP MAP_ANONYMOUS)
else()
    check_c_source_compiles(
        "
            /* OPENBSD WORKAROUND - DND*/
            #include <sys/types.h>
            /* OPENBSD WORKAROUND - END*/
            #include <sys/mman.h>
            int main(void)
            {
                mmap((void *)0, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
                return 0;
            }
        "
        HAVE_MMAP_MAP_ANON
    )
    if(HAVE_MMAP_MAP_ANON)
        set(ANONYMOUS_MAP MAP_ANON)
    endif()
endif()

# Check for getting the pagesize.
check_symbol_exists(getpagesize unistd.h HAVE_GETPAGESIZE)
check_c_source_compiles(
    "
        #include <sys/types.h>
        #if HAVE_UNISTD_H
        #include <unistd.h>
        #endif
        int main(void)
        {
            int x = sysconf(_SC_PAGESIZE);
            return 0;
        }
    "
    HAVE_SYSCONF_SC_PAGESIZE
)

# Check for mempool support
if(DISABLE_MPOOL)
    message("****** mempool support disabled (DISABLE_MPOOL enabled)")
elseif(NOT HAVE_MMAP)
    message("****** mempool support disabled (mmap() not available or not usable)")
elseif(NOT HAVE_GETPAGESIZE AND NOT HAVE_SYSCONF_SC_PAGESIZE)
    message("****** mempool support disabled (pagesize cannot be determined)")
elseif(NOT HAVE_MMAP_MAP_ANON AND NOT HAVE_MMAP_MAP_ANONYMOUS)
    message("****** mempool support disabled (anonymous mmap not available)")
else()
    set(USE_MPOOL 1)
endif()
