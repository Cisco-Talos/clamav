#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif
#include "version.h"

const char *cl_retver(void)
{
	if(!strncmp("devel-",VERSION,6) && strcmp("exported",REPO_VERSION)) {
		return REPO_VERSION;
	}
	/* it is a release, or we have nothing better */
	return VERSION;
}
