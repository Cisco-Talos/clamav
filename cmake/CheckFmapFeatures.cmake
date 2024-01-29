include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckCSourceCompiles)

# Extra -D Compile Definitions for check_c_source_compiles()
set(CMAKE_REQUIRED_DEFINITIONS "")
if(HAVE_SYS_TYPES_H)
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS};-DHAVE_SYS_TYPES_H=1")
endif()
if(HAVE_SYS_STAT_H)
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS};-DHAVE_SYS_STAT_H=1")
endif()

# Check for mmap() support, required for HAVE_MPOOL.
#
# checks for private fixed mappings, we don't need fixed mappings,
# so check only whether private mappings work.
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
            #define ERR(e) do { status = e; goto done; } while(0)
            int main(void)
            {
                char *data = NULL, *data2 = MAP_FAILED, *data3 = NULL;
                size_t i, datasize = 1024;
                int fd = -1, status = 0;

                /* First, make a file with some known garbage in it. */
                data = (char*) malloc(datasize);
                if(!data)
                    ERR(1);
                for(i=0;i<datasize;i++)
                    *(data + i) = rand();
                umask(0);
                fd = creat(\"conftest.mmap\", 0600);
                if(fd < 0)
                    ERR(1);
                if(write (fd, data, datasize) != datasize)
                    ERR(1);
                close(fd);
                fd = open(\"conftest.mmap\", O_RDWR);
                if (fd < 0)
                    ERR(1);
                /* Next, try to create a private map of the file. If we can, also make sure that
                   we see the same garbage.  */
                data2 = mmap(NULL, datasize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE, fd, 0L);
                if(data2 == MAP_FAILED)
                    ERR(2);
                for(i=0;i<datasize;i++)
                    if(*(data + i) != *(data2+ i))
                        ERR(3);
                /* Finally, make sure that changes to the mapped area do not
                   percolate back to the file as seen by read().
                   (This is a bug on some variants of i386 svr4.0.)  */
                for (i = 0; i < datasize; ++i)
                    *(data2 + i) = *(data2 + i) + 1;
                data3 = (char*) malloc(datasize);
                if(!data3)
                    ERR(1);
                if(read (fd, data3, datasize) != datasize)
                    ERR(1);
                for(i=0;i<datasize;i++)
                    if(*(data + i) != *(data3 + i))
                        ERR(3);
            done:
                if(fd >= 0)
                    close(fd);
                if(data3)
                    free(data3);
                if(data2 != MAP_FAILED)
                    munmap(data2, datasize);
                if(data)
                    free(data);
                return status;
            }
        "
        HAVE_MMAP
    )
endif()

# Check the flag name for the ANONYMOUS_MAP feature.
if(HAVE_MMAP)
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
endif()

# Check for getting the pagesize.
check_symbol_exists(getpagesize unistd.h HAVE_GETPAGESIZE)
check_c_source_compiles(
    "
        #include <sys/types.h>
        #include <unistd.h>
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
