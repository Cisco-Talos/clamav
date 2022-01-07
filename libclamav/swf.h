/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
 *
 *  The code is based on Flasm, command line assembler & disassembler of Flash
 *  ActionScript bytecode Copyright (c) 2001 Opaque Industries, (c) 2002-2007
 *  Igor Kogan, (c) 2005 Wang Zhen. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or other
 *  materials provided with the distribution.
 *  - Neither the name of the Opaque Industries nor the names of its contributors may
 *  be used to endorse or promote products derived from this software without specific
 *  prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 *  SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 *  WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __SWF_H
#define __SWF_H

#include "others.h"

int cli_scanswf(cli_ctx *ctx);

typedef enum {
    TAG_END                 = 0,
    TAG_SHOWFRAME           = 1,
    TAG_DEFINESHAPE         = 2,
    TAG_FREECHARACTER       = 3,
    TAG_PLACEOBJECT         = 4,
    TAG_REMOVEOBJECT        = 5,
    TAG_DEFINEBITS          = 6,
    TAG_DEFINEBUTTON        = 7,
    TAG_JPEGTABLES          = 8,
    TAG_SETBACKGROUNDCOLOR  = 9,
    TAG_DEFINEFONT          = 10,
    TAG_DEFINETEXT          = 11,
    TAG_DOACTION            = 12,
    TAG_DEFINEFONTINFO      = 13,
    TAG_DEFINESOUND         = 14,
    TAG_STARTSOUND          = 15,
    TAG_STOPSOUND           = 16,
    TAG_DEFINEBUTTONSOUND   = 17,
    TAG_SOUNDSTREAMHEAD     = 18,
    TAG_SOUNDSTREAMBLOCK    = 19,
    TAG_DEFINEBITSLOSSLESS  = 20,
    TAG_DEFINEBITSJPEG2     = 21,
    TAG_DEFINESHAPE2        = 22,
    TAG_DEFINEBUTTONCXFORM  = 23,
    TAG_PROTECT             = 24,
    TAG_PATHSAREPOSTSCRIPT  = 25,
    TAG_PLACEOBJECT2        = 26,
    TAG_REMOVEOBJECT2       = 28,
    TAG_SYNCFRAME           = 29,
    TAG_FREEALL             = 31,
    TAG_DEFINESHAPE3        = 32,
    TAG_DEFINETEXT2         = 33,
    TAG_DEFINEBUTTON2       = 34,
    TAG_DEFINEBITSJPEG3     = 35,
    TAG_DEFINEBITSLOSSLESS2 = 36,
    TAG_DEFINEEDITTEXT      = 37,
    TAG_DEFINEVIDEO         = 38,
    TAG_DEFINEMOVIECLIP     = 39,
    TAG_NAMECHARACTER       = 40,
    TAG_SERIALNUMBER        = 41,
    TAG_DEFINETEXTFORMAT    = 42,
    TAG_FRAMELABEL          = 43,
    TAG_SOUNDSTREAMHEAD2    = 45,
    TAG_DEFINEMORPHSHAPE    = 46,
    TAG_GENFRAME            = 47,
    TAG_DEFINEFONT2         = 48,
    TAG_GENCOMMAND          = 49,
    TAG_DEFINECOMMANDOBJ    = 50,
    TAG_CHARACTERSET        = 51,
    TAG_FONTREF             = 52,
    TAG_EXPORTASSETS        = 56,
    TAG_IMPORTASSETS        = 57,
    TAG_ENABLEDEBUGGER      = 58,
    TAG_INITMOVIECLIP       = 59,
    TAG_DEFINEVIDEOSTREAM   = 60,
    TAG_VIDEOFRAME          = 61,
    TAG_DEFINEFONTINFO2     = 62,
    TAG_DEBUGID             = 63,
    TAG_ENABLEDEBUGGER2     = 64,
    TAG_SCRIPTLIMITS        = 65,
    TAG_SETTABINDEX         = 66,
    TAG_DEFINESHAPE4        = 67,
    TAG_FILEATTRIBUTES      = 69,
    TAG_PLACEOBJECT3        = 70,
    TAG_IMPORTASSETS2       = 71,
    TAG_DEFINEFONTINFO3     = 73,
    TAG_DEFINETEXTINFO      = 74,
    TAG_DEFINEFONT3         = 75,
    TAG_AVM2DECL            = 76,
    TAG_METADATA            = 77,
    TAG_SLICE9              = 78,
    TAG_AVM2ACTION          = 82,
    TAG_DEFINESHAPE5        = 83,
    TAG_DEFINEMORPHSHAPE2   = 84,
    TAG_DEFINESFLABELDATA   = 86,
    TAG_DEFINEBINARYDATA    = 87,
    TAG_DEFINEFONTNAME      = 88,
    TAG_STARTSOUND2         = 89,
    TAG_DEFINEBITSJPEG4     = 90,
    TAG_DEFINEFONT4         = 91,
    TAG_ENABLETELEMETRY     = 93,
    TAG_DEFINEBITSPTR       = 1023,
    TAG_UNKNOWN             = 9999
} tag_id;

// clang-format off
static const struct tag_names_s {
    const char *name;
    tag_id  id;
} tag_names[] = {
    { "TAG_END",                 TAG_END                },
    { "TAG_SHOWFRAME",           TAG_SHOWFRAME          },
    { "TAG_DEFINESHAPE",         TAG_DEFINESHAPE        },
    { "TAG_FREECHARACTER",       TAG_FREECHARACTER      },
    { "TAG_PLACEOBJECT",         TAG_PLACEOBJECT        },
    { "TAG_REMOVEOBJECT",        TAG_REMOVEOBJECT       },
    { "TAG_DEFINEBITS",          TAG_DEFINEBITS         },
    { "TAG_DEFINEBUTTON",        TAG_DEFINEBUTTON       },
    { "TAG_JPEGTABLES",          TAG_JPEGTABLES         },
    { "TAG_SETBACKGROUNDCOLOR",  TAG_SETBACKGROUNDCOLOR },
    { "TAG_DEFINEFONT",          TAG_DEFINEFONT         },
    { "TAG_DEFINETEXT",          TAG_DEFINETEXT         },
    { "TAG_DOACTION",            TAG_DOACTION           },
    { "TAG_DEFINEFONTINFO",      TAG_DEFINEFONTINFO     },
    { "TAG_DEFINESOUND",         TAG_DEFINESOUND        },
    { "TAG_STARTSOUND",          TAG_STARTSOUND         },
    { "TAG_STOPSOUND",           TAG_STOPSOUND          },
    { "TAG_DEFINEBUTTONSOUND",   TAG_DEFINEBUTTONSOUND  },
    { "TAG_SOUNDSTREAMHEAD",     TAG_SOUNDSTREAMHEAD    },
    { "TAG_SOUNDSTREAMBLOCK",    TAG_SOUNDSTREAMBLOCK   },
    { "TAG_DEFINEBITSLOSSLESS",  TAG_DEFINEBITSLOSSLESS },
    { "TAG_DEFINEBITSJPEG2",     TAG_DEFINEBITSJPEG2    },
    { "TAG_DEFINESHAPE2",        TAG_DEFINESHAPE2       },
    { "TAG_DEFINEBUTTONCXFORM",  TAG_DEFINEBUTTONCXFORM },
    { "TAG_PROTECT",             TAG_PROTECT            },
    { "TAG_PATHSAREPOSTSCRIPT",  TAG_PATHSAREPOSTSCRIPT },
    { "TAG_PLACEOBJECT2",        TAG_PLACEOBJECT2       },
    { "TAG_REMOVEOBJECT2",       TAG_REMOVEOBJECT2      },
    { "TAG_SYNCFRAME",           TAG_SYNCFRAME          },
    { "TAG_FREEALL",             TAG_FREEALL            },
    { "TAG_DEFINESHAPE3",        TAG_DEFINESHAPE3       },
    { "TAG_DEFINETEXT2",         TAG_DEFINETEXT2        },
    { "TAG_DEFINEBUTTON2",       TAG_DEFINEBUTTON2      },
    { "TAG_DEFINEBITSJPEG3",     TAG_DEFINEBITSJPEG3    },
    { "TAG_DEFINEBITSLOSSLESS2", TAG_DEFINEBITSLOSSLESS2},
    { "TAG_DEFINEEDITTEXT",      TAG_DEFINEEDITTEXT     },
    { "TAG_DEFINEVIDEO",         TAG_DEFINEVIDEO        },
    { "TAG_DEFINEMOVIECLIP",     TAG_DEFINEMOVIECLIP    },
    { "TAG_NAMECHARACTER",       TAG_NAMECHARACTER      },
    { "TAG_SERIALNUMBER",        TAG_SERIALNUMBER       },
    { "TAG_DEFINETEXTFORMAT",    TAG_DEFINETEXTFORMAT   },
    { "TAG_FRAMELABEL",          TAG_FRAMELABEL         },
    { "TAG_SOUNDSTREAMHEAD2",    TAG_SOUNDSTREAMHEAD2   },
    { "TAG_DEFINEMORPHSHAPE",    TAG_DEFINEMORPHSHAPE   },
    { "TAG_GENFRAME",            TAG_GENFRAME           },
    { "TAG_DEFINEFONT2",         TAG_DEFINEFONT2        },
    { "TAG_GENCOMMAND",          TAG_GENCOMMAND         },
    { "TAG_DEFINECOMMANDOBJ",    TAG_DEFINECOMMANDOBJ   },
    { "TAG_CHARACTERSET",        TAG_CHARACTERSET       },
    { "TAG_FONTREF",             TAG_FONTREF            },
    { "TAG_EXPORTASSETS",        TAG_EXPORTASSETS       },
    { "TAG_IMPORTASSETS",        TAG_IMPORTASSETS       },
    { "TAG_ENABLEDEBUGGER",      TAG_ENABLEDEBUGGER     },
    { "TAG_INITMOVIECLIP",       TAG_INITMOVIECLIP      },
    { "TAG_DEFINEVIDEOSTREAM",   TAG_DEFINEVIDEOSTREAM  },
    { "TAG_VIDEOFRAME",          TAG_VIDEOFRAME         },
    { "TAG_DEFINEFONTINFO2",     TAG_DEFINEFONTINFO2    },
    { "TAG_DEBUGID",             TAG_DEBUGID            },
    { "TAG_ENABLEDEBUGGER2",     TAG_ENABLEDEBUGGER2    },
    { "TAG_SCRIPTLIMITS",        TAG_SCRIPTLIMITS       },
    { "TAG_SETTABINDEX",         TAG_SETTABINDEX        },
    { "TAG_DEFINESHAPE4",        TAG_DEFINESHAPE4       },
    { "TAG_FILEATTRIBUTES",      TAG_FILEATTRIBUTES     },
    { "TAG_PLACEOBJECT3",        TAG_PLACEOBJECT3       },
    { "TAG_IMPORTASSETS2",       TAG_IMPORTASSETS2      },
    { "TAG_DEFINEFONTINFO3",     TAG_DEFINEFONTINFO3    },
    { "TAG_DEFINETEXTINFO",      TAG_DEFINETEXTINFO     },
    { "TAG_DEFINEFONT3",         TAG_DEFINEFONT3        },
    { "TAG_AVM2DECL",            TAG_AVM2DECL           },
    { "TAG_METADATA",            TAG_METADATA           },
    { "TAG_SLICE9",              TAG_SLICE9             },
    { "TAG_AVM2ACTION",          TAG_AVM2ACTION         },
    { "TAG_DEFINESHAPE5",        TAG_DEFINESHAPE5       },
    { "TAG_DEFINEMORPHSHAPE2",   TAG_DEFINEMORPHSHAPE2  },
    { "TAG_DEFINESFLABELDATA",   TAG_DEFINESFLABELDATA  },
    { "TAG_DEFINEBINARYDATA",    TAG_DEFINEBINARYDATA   },
    { "TAG_DEFINEFONTNAME",      TAG_DEFINEFONTNAME     },
    { "TAG_STARTSOUND2",         TAG_STARTSOUND2        },
    { "TAG_DEFINEBITSJPEG4",     TAG_DEFINEBITSJPEG4    },
    { "TAG_DEFINEFONT4",         TAG_DEFINEFONT4        },
    { "TAG_ENABLETELEMETRY",     TAG_ENABLETELEMETRY    },
    { "TAG_DEFINEBITSPTR",       TAG_DEFINEBITSPTR      },
    { NULL,                      TAG_UNKNOWN            },
};
// clang-format on

// clang-format off
#define SWF_ATTR_USENETWORK                 0x01
#define SWF_ATTR_RELATIVEURLS               0x02
#define SWF_ATTR_SUPPRESSCROSSDOMAINCACHE   0x04
#define SWF_ATTR_ACTIONSCRIPT3              0x08
#define SWF_ATTR_HASMETADATA                0x10
#define SWF_ATTR_USEDIRECTBLIT              0x20
#define SWF_ATTR_USEGPU                     0x40
// clang-format on

#endif
