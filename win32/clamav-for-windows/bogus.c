#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clscanapi.h"

typedef void (CALL_CONVENTION *CLAM_PASSWORD_CALLBACK)(int objectType, const wchar_t *pObjectName, wchar_t *pPassword, int *pPasswordLen, void *context);

int CLAMAPI Scan_SetPasswordCallback(CClamAVScanner *pScanner, CLAM_PASSWORD_CALLBACK pfnCallback, void *pContext) {
    return CLAMAPI_SUCCESS;
}

int CLAMAPI Scan_ScanObjectInMemory(CClamAVScanner *pScanner, const void *pObject, unsigned int objectSize, int objectType, int action, int impersonatePID, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    return CLAMAPI_SUCCESS;
}