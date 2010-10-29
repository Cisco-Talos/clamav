/* common warning snippet for all osx direct includes */

#ifndef wxOSX_USE_CARBON
#error "this files should only be included after platform.h was included"
#endif

#ifndef _WX_PRIVATE_OSX_H_
#define _WX_PRIVATE_OSX_H_

#if wxOSX_USE_IPHONE
    #include "wx/osx/iphone/private.h"
#elif wxOSX_USE_CARBON
    #include "wx/osx/carbon/private.h"
#elif wxOSX_USE_COCOA
    #include "wx/osx/cocoa/private.h"
#endif

#endif
