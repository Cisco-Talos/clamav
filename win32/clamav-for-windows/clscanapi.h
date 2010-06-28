/*
 * Copyright (C) 2010 Sourcefire, Inc.
 * Authors: aCaB <acab@clamav.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

// Template for 3rd party engines to integrate with Immunet
// TODO: Replace <MOD> with engine specific name
/*
Engine/API Requirements:

 R1) Ability to invoke scans

		- with callbacks where callback is invoked several times (even during scanning a single PE file). The scan engine could invoke callbacks during the following states:
			- state 1: after unpacking (if packed)
			- state 2: after emulation (if emulation is supported)
			- state 3: after scan is complete
			- state 4: after requested action is performed (only in case of infection)
			For archive, installers, compound files the callback should be invoked for each file. Each file may cause the callback to be invoked more than once.

		- without callbacks, it should be possible to retrieve additional information about file that was scanned
			i) infections found after the scan (ex: using MOD_SCAN_INFO_LIST)
			ii) Unpacked file (in case the original file was packed)
		  There probably will be some settings to limit large memory usage in this case. For example, if a large archive file with 1000 infected files
		  is scanned, it may be unrealistic to return information for all the files. Probably MAX_INFECTION_COUNT setting will exist to limit passing
		  back such information

  R2) The callbacks should be asynchronous (i.e. a separate thread with same engine instance should be able to scan a file without waiting
	  even when the first file callback has not returned
	  Use case: Typically, in callback it is expected to make connection to the cloud before taking action. Since, the cloud query can take few ms, it
	  should be possible for another thread with same engine instance to scan a separate file without any interference.

  R3) The disinfection/delete should be supported asynchronously. The engine should be able to perform state 1 to state 3 in sequence and state 4 
	  could be performed at a later stage.
	  Use case: In case of system scans, drive scans there is a good chance that more than one infection is found. Instead of asking user each time
	  a list can be generated in the end giving the user the choice to take action. If the user chooses to disinfect/delete the disinfection action
	  should happen without performing any additional scan.
		  
  R4) The definitions should ideally not consume more than 30MB in memory

  R5) The scan engine should ideally not consume more than 50ms for scanning individual files in most cases
*/
#ifndef _CLAM_SCAN_API_H
#define _CLAM_SCAN_API_H

#define CLAMAPI __declspec(dllexport)

#ifndef CALL_CONVENTION
#define CALL_CONVENTION __cdecl
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO: define constants like type of malware, type of object, error code etc here

#define CLAMAPI_SUCCESS	0
#define CLAMAPI_FAILURE	1

#define CLAMAPI_OBJECT_TYPE_FILE 1

#define CLAM_OPTION_SCAN_MODE 0x0
#define CLAM_SCAN_FULL 0x0
#define CLAM_SCAN_LIGHT  0x1

#define CLAM_OPTION_SCAN_ARCHIVE	0x00000001
#define CLAM_OPTION_SCAN_PACKED		0x00000002
#define CLAM_OPTION_SCAN_EMAIL		0x00000004
#define CLAM_OPTION_SCAN_DEEP		0x00000008

#define CLAMAPI_DISINFECT_ONLY 0x10
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// An example structure that external module should fill. This can be used by Immunet interface either during callback
// or once the scan API function has completed
// TODO: Add any fields as required

typedef struct _CLAM_SCAN_INFO
{
	// size of this structure
	int cbSize;

	// Based on this type, pObject field is interpreted
	// ex: stream in a compound object, file in an archive, embedded file in installer etc
	int objectType;

	// archive flags. In case the file being scanned is archive file set the flags accordingly
	int archiveFlags;

	// compressionFlags flags. In case the file being scanned is packed set the flags accordingly
	int compressionFlags;

	// installerFlags flags. In case the file being scanned is an installer (MSI, NSIS etc) set the flags accordingly
	int installerFlags;

	// path to the file being scanned (C:\test.zip)
	const wchar_t *pObjectPath;

	// path of inner file relative to file being scanned
	// valid only for certain object types (ex: installers, compound objects, archive files etc
	const wchar_t *pInnerObjectPath;

	// a state machine kind of variable
	// If a callback is registered, it can be called during any one of the following states
	// unpack complete -> emulation complete -> scan complete -> action result complete
	int scanStatus;

	// status code corresponding to scanStatus
	int errorCode;

	// interpretation could depend on objectType. Maybe just base pointer to file loaded in memory.
	// Can this work for all cases?
	void *pObject;

	// size of object
	unsigned long objectLength;

	// type of threat (adware, malware etc)
	int threatType;

	// threatname
	const wchar_t *pThreatName;
}CLAM_SCAN_INFO, *PCLAM_SCAN_INFO;

// list of CLAM_SCAN_INFO items
// Typical use: If no callback is registered and an archive file is scanned, this list corresponds to each infected file found
typedef struct _CLAM_SCAN_INFO_LIST
{
	// number of CLAM_SCAN_INFO structures present
	int cbCount;

	// pointer to first CLAM_SCAN_INFO structure
	PCLAM_SCAN_INFO pInfoList;
}CLAM_SCAN_INFO_LIST, *PCLAM_SCAN_INFO_LIST;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Callback prototypes

/*
 * MANDATORY SUPPORT
 * callback that can be registered to be invoked by the scan engine
 * Parameters: 
 * INPUT @param pObjectInfo : all relevant information of the file being scanned
 * OUTPUT @param scanAction : action to be taken as determined by callback
 * INPUT @param context : any context to be passed to scan callback
 */
typedef void (CALL_CONVENTION *CLAM_SCAN_CALLBACK)(const CLAM_SCAN_INFO *pObjectInfo, int *scanAction, void *context);

/*
 * OPTIONAL SUPPORT
 * callback that can be registered to be invoked by the scan engine
 * Parameters: 
 * INPUT @param objectType : object type
 * INPUT @param pObjectName : name of object (typically filename)
 * INPUT @param pPassword : input buffer to hold password
 * INPUT/OUTPUT @param pPasswordLen : on input consists of length of password buffer. The callback fills this with actual length.
 * INPUT @param context : any context to be passed to scan callback
 */
typedef void (CALL_CONVENTION *CLAM_PASSWORD_CALLBACK)(int objectType, const wchar_t *pObjectName, wchar_t *pPassword, int *pPasswordLen, void *context);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Function prototypes

#ifdef __cplusplus
extern "C" {
#endif

// In future this can be extended to C++ style interface
// CCLAMScanner refers to Scanner instance
#define CClamAVScanner void

/*
 * MANDATORY SUPPORT
 * Load scan engine defs
 * Parameters: 
 * INPUT @param pEnginesFolder : path where defs are located
 * INPUT @param pLicenseKey : license key blob
 */
int CLAMAPI Scan_Initialize(const wchar_t *pEnginesFolder, const wchar_t *pLicenseKey);

/*
 * MANDATORY SUPPORT
 * Unload scan engine defs, which were loaded using Scan_Initialize
 * Parameters: None
 */
int CLAMAPI Scan_Uninitialize();

/*
 * MANDATORY SUPPORT
 * Create scan engine instance. 
 * The engine instances should have the ability to be shared across threads
 * If synchronization is not done internally, it should be identified as such
 * OUTPUT @param ppScanner : location to hold opaque object
 */
int CLAMAPI Scan_CreateInstance(CClamAVScanner **ppScanner);

/*
 * MANDATORY SUPPORT
 * Destroy scan engine instance. 
 * INPUT @param pScanner : opaque object
 */
int CLAMAPI Scan_DestroyInstance(CClamAVScanner *pScanner);

/*
 * MANDATORY SUPPORT
 * Set callback that is invoked when file is being scanned
 * The callback can be invoked multiple times while scanning a file
 *	- state 1: after unpacking (if packed)
 *	- state 2: after emulation (if emulation is supported)
 *	- state 3: after scan is complete
 *	- state 4: after requested action is performed (only in case of infection)
 * For archive, installers, compound files the callback should be invoked for each file. Each file can cause the callback to be invoked more than once.
 * INPUT @param pScanner : opaque object
 * INPUT @param pfnCallback : callback function
 * INPUT @param pContext : context to be passed to callback function
 */
int CLAMAPI Scan_SetScanCallback(CClamAVScanner *pScanner, CLAM_SCAN_CALLBACK pfnCallback, void *pContext);

/*
 * OPTIONAL SUPPORT. Required only if password callbacks are supported
 * Set callback that is invoked if the file to be scanned requires password input
 * INPUT @param pScanner : opaque object
 * INPUT @param pfnCallback : callback function
 * INPUT @param pContext : context to be passed to callback function
 */
int CLAMAPI Scan_SetPasswordCallback(CClamAVScanner *pScanner, CLAM_PASSWORD_CALLBACK pfnCallback, void *pContext);

/*
 * MANDATORY SUPPORT
 * Scan object using path
 * INPUT @param pScanner : opaque object
 * INPUT @param pObjectPath : path to object
 * INPUT @param objectType : object type
 * INPUT @param action : attempt cleanup (default action is taken if this is not set and no callback is registered)
 * INPUT @param impersonatePID : impersonate the process (incase file is not accessible to current thread)
 * OUTPUT @param pScanStatus : indicates status of scan
 * OUTPUT @param pInfoList : list containing additional information about file that was scanned
 */
int CLAMAPI Scan_ScanObject(CClamAVScanner *pScanner, const wchar_t *pObjectPath, int objectType, int action, int impersonatePID, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList);

/*
 * MANDATORY SUPPORT
 * Scan object using object handle
 * INPUT @param pScanner : opaque object
 * INPUT @param pObject : handle to object
 * INPUT @param objectType : object type
 * INPUT @param action : attempt cleanup (default action is taken if this is not set and no callback is registered)
 * INPUT @param impersonatePID : impersonate the process (incase file is not accessible to current thread)
 * OUTPUT @param pScanStatus : indicates status of scan
 * OUTPUT @param pInfoList : list containing additional information about file that was scanned
 */
int CLAMAPI Scan_ScanObjectByHandle(CClamAVScanner *pScanner, const void *pObject, int objectType, int action, int impersonatePID, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList);

/*
 * OPTIONAL SUPPORT
 * Scan object in memory
 * INPUT @param pScanner : opaque object
 * INPUT @param pObject : handle to object
 * INPUT @param objectSize : size of object in memory
 * INPUT @param objectType : object type
 * INPUT @param action : attempt cleanup (default action is taken if this is not set and no callback is registered)
 * INPUT @param impersonatePID : impersonate the process (incase file is not accessible to current thread)
 * OUTPUT @param pScanStatus : indicates status of scan
 * OUTPUT @param pInfoList : list containing additional information about file that was scanned
 */
int CLAMAPI Scan_ScanObjectInMemory(CClamAVScanner *pScanner, const void *pObject, unsigned int objectSize, int objectType, int action, int impersonatePID, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList);

/*
 * MANDATORY SUPPORT
 * Destroy memory allocated when malicious objects are found during scan
 * INPUT @param pScanner : opaque object
 * INPUT/OUTPUT @param pInfoList : list to be freed
 */
int CLAMAPI Scan_DeleteScanInfo(CClamAVScanner *pScanner, PCLAM_SCAN_INFO_LIST pInfoList);

/*
 * Get integer based scanning options
 * ex: License Expiration Time, Count of DB signatures, Last updated time for DB, Major, Minor version of scan library
 * INPUT @param scanner : opaque object
 * INPUT @param option : option enum
 * INPUT @param value : location to store value
 * INPUT @param inputLength : size of input buffer
 * OUTPUT @param outLength : mimimum size require to store data
 */
int CLAMAPI Scan_GetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength, unsigned long *outLength);

/*
 * Set integer based scanning options
 * ex: scan Archives, scan packed samples, scan e-mail databases, scan installers
 * INPUT @param pScanner : opaque object
 * INPUT @param option : option enum
 * INPUT @param value : location to store value
 * INPUT @param inputLength : size of input value
 */
int CLAMAPI Scan_SetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _CLAM_SCAN_API_H */
