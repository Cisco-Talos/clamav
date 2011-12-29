#ifndef __ASN1_H
#define __ASN1_H

#include <stdio.h>
#include <time.h>

#include "fmap.h"
#include "sha1.h"
#include "crtmgr.h"

int asn1_parse_mscat(FILE *f, crtmgr *c);

#endif
