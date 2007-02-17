#ifndef _SNPRINTF_H
#define _SNPRINTF_H

#include "clamav-config.h"

#include <sys/types.h> /* For size_t */

#ifndef HAVE_SNPRINTF
int snprintf(char *str, size_t count, const char *fmt, ...);
#endif /* !HAVE_SNPRINTF */

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *str, size_t count, const char *fmt, va_list args);
#endif /* !HAVE_SNPRINTF */

#endif /* _SNPRINTF_H */
