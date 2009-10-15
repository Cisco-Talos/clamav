/* just a draft for now */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "pthread.h"

BOOL APIENTRY DllMain(HMODULE hm, DWORD why, LPVOID rsrv) {
    WSADATA wsa;
    switch (why) {
    case DLL_PROCESS_ATTACH:
	if(WSAStartup(MAKEWORD(2,2), &wsa))
	    return FALSE;
	return pthread_win32_process_attach_np();
	break;

    case DLL_THREAD_ATTACH:
	return pthread_win32_thread_attach_np ();
	break;

    case DLL_THREAD_DETACH:
	return pthread_win32_thread_detach_np ();
	break;

    case DLL_PROCESS_DETACH:
	WSACleanup();
	pthread_win32_thread_detach_np ();
	return pthread_win32_process_detach_np ();
	break;
    }
}
