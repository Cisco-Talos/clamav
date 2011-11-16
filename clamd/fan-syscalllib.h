#ifndef __FANOTIFY_SYSCALL_LIB
#define __FANOTIFY_SYSCALL_LIB

#include <unistd.h>
#include <linux/types.h>

#if defined(__x86_64__)
# define __NR_fanotify_init	300
# define __NR_fanotify_mark	301
#elif defined(__i386__)
# define __NR_fanotify_init	338
# define __NR_fanotify_mark	339
#else
# error "System call numbers not defined for this architecture"
#endif

static inline int fanotify_init(unsigned int flags, unsigned int event_f_flags)
{
	return syscall(__NR_fanotify_init, flags, event_f_flags);
}

static inline int fanotify_mark(int fanotify_fd, unsigned int flags, __u64 mask,
				int dfd, const char *pathname)
{
	return syscall(__NR_fanotify_mark, fanotify_fd, flags, mask,
		       dfd, pathname);
}
#endif
