#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif
#include "clamav.h"
#include "version.h"

#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

/* libclamav's version is always the SVN revision (if available) */
const char *cl_retver(void)
{
	return REPO_VERSION""VERSION_SUFFIX;
}
