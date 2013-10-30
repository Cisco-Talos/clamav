#if !defined(_LIBCLAMAV_HOSTID_H)
#define _LIBCLAMAV_HOSTID_H

struct device {
    char *name;
    char mac[19];
};

struct device *get_devices(void);

#if !HAVE_SYSCTLBYNAME
char *internal_get_host_id(void);
#endif

#endif
