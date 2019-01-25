//
//  libfreshclam.h
//  freshclam
//
//  Created by msachedi on 2/3/14.
//  Copyright (C) 2014-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
//

#ifndef freshclam_libfreshclam_h
#define freshclam_libfreshclam_h

int download_with_opts(struct optstruct *opts, const char* db_path, const char* db_owner);
struct optstruct *optadditem(const char *name, const char *arg, int verbose, int toolmask, int ignore,
                          struct optstruct *oldopts);
#endif
