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

#ifndef _CLSCANAPI_H
#define _CLSCANAPI_H


/**************************************************************************************
                                   CLAMAPI interface
***************************************************************************************/

/* CLAMAPI calling convention. Please do not touch */
#ifndef CALL_CONVENTION
#define CALL_CONVENTION __cdecl
#endif

#ifndef CLAMAPI
#define CLAMAPI
#endif


/* CLAMAPI - return codes */
/* Always check for the return value of CLAMAPI's 
 * Possible values are:
 * - return_value == CLAMAPI_SUCCESS: API succeded
 * - return_value != CLAMAPI_SUCCESS: API failed (call Scan_GetErrorMsg(return_value) to retrieve the error message)
 */
#define CLAMAPI_SUCCESS 0


/* CLAMAPI LIMITS */
/* List of limits configurable via Scan_SetLimit and readable via Scan_GetLimit (see below) */
enum CLAM_LIMIT_TYPE {
    CLAM_LIMIT_FILESIZE,
    CLAM_LIMIT_SCANSIZE,
    CLAM_LIMIT_RECURSION
};


/* CLAMAPI SCAN OPTIONS */
/* List of options settable via Scan_SetOption and retrievable via Scan_GetOption (see below)
 * All the options have a corresponding unsigned int value (0 = option disabled / non 0 = option enabled)
 */
enum CLAM_SCAN_OPTIONS {
    CLAM_OPTION_SCAN_ARCHIVE,	/* Enable/disable scanning of archive files (zip, arj, rar, cab, etc.) */
    CLAM_OPTION_SCAN_MAIL,	/* Enable/disable scanning of archive mail files (mbox, eml) */
    CLAM_OPTION_SCAN_OLE2,	/* Enable/disable scanning of OLE2 files (mostly msi and doc) */
    CLAM_OPTION_SCAN_HTML,	/* Enable/disable scanning of html files */
    CLAM_OPTION_SCAN_PE,	/* Enable/disable scanning of archive PE (aka windows) executables */
    CLAM_OPTION_SCAN_ALGORITHMIC, /* Enable/disable scanning for certain viruses and exploits */
    CLAM_OPTION_SCAN_ELF,	/* Enable/disable scanning of archive ELF (aka linux) executables */ /* FIXME: is this needed */
    CLAM_OPTION_SCAN_PDF	/* Enable/disable scanning of Adobe PDF files */
};
/* NOTE: by default (i.e. before calling Scan_SetOption) ALL the options are ENABLED! */


/* CLAMAPI SCAN PHASES */
/* Define the scan phase to which the returned results refer to */
typedef enum _CLAM_SCAN_PHASE {
    SCAN_PHASE_INITIAL,	 /* Right before ClamAV starts scanning the entry (outer) file - in scan callback mode only */
    SCAN_PHASE_PRESCAN,	 /* Right before ClamAV starts scanning the current file - in scan callback mode only */
    SCAN_PHASE_POSTSCAN, /* After ClamAV has scanned the current file - in scan callback mode only */
    SCAN_PHASE_FINAL	 /* After ClamAV has scanned the entry (outer) file (callback) and upon returning from ScanObject */
} CLAM_SCAN_PHASE;


/* CLAMAPI SCAN RESULT VALUES */
/* Value returned by ScanObject */
#define CLAM_CLEAN 0
#define CLAM_INFECTED 1

/* CLAMAPI RESULT DEFINITIONS */
/* The CLAM_SCAN_INFO structure is used:
 * - to return scan results
 * - to pass progress data and results to the scan callback
 */
typedef struct _CLAM_SCAN_INFO {
    /** The size of this structure: to be set to sizeof(CLAM_SCAN_INFO) **/
    /* Presence: ALWAYS */
    int cbSize;

    /** A single field that can store information regarding packers, installers, compound objects etc **/
    int flags;

    /** The phase to which the results refer to **/
    /* Presence: ALWAYS */
    CLAM_SCAN_PHASE scanPhase;

    /** Error condition **/
    /* Possible values: CLAMAPI_SUCCESS if no error; call Scan_GetErrorMsg(errorCode)
     * to retrieve the error message */
    /* Presence: ALWAYS */
    int errorCode;

    /** The type of threat (e.g. "Adware", "Trojan", etc.) **/
    /* For clean files this is set to NULL */
    /* Presence: SCAN_PHASE_POSTSCAN, SCAN_PHASE_FINAL */
    const wchar_t *pThreatType;

    /** The name of threat (i.e. virus name) **/
    /* For clean files this is set to NULL */
    /* Presence: SCAN_PHASE_POSTSCAN, SCAN_PHASE_FINAL */
    const wchar_t *pThreatName;

    /** The handle of the file being processed **/
    /* Note #1: the handle MUST BE CLOSED by the caller, at any point
     * Note #2: the has FILE_ATTRIBUTE_TEMPORARY and FILE_FLAG_DELETE_ON_CLOSE attributes
     * Note #3: the file pointer is guaranteed to be set at the begin of
     *          the file and its position needs not to be reset */
    /* Presence: SCAN_PHASE_PRESCAN, SCAN_PHASE_POSTSCAN */
    HANDLE object;

    /** An unique identifier for the file being processed **/
    /* Provided for mapping purposes (type HANDLE for legacy reasons) */
    /* Presence: SCAN_PHASE_PRESCAN, SCAN_PHASE_POSTSCAN */
    HANDLE objectId;
    
    /** The path of inner file relative to file being scanned **/
    /* This applies only to archive for which internal names can be retrieved and is NULL otherwise */
    /* Presence: ALWAYS */
    const wchar_t *pInnerObjectPath;

    /** File type **/
    /* Presence; SCAN_PHASE_PRESCAN */
    _int64 filetype[2];

} CLAM_SCAN_INFO, *PCLAM_SCAN_INFO;
/* NOTE: all the objects within the above structure are guaranteed to be available and
 *       valid until the callback returns (SCAN_PHASE_PRESCAN and SCAN_PHASE_POSTSCAN) or
 *       Scan_DeleteScanInfo is called (SCAN_PHASE_FINAL) */


/* List of CLAM_SCAN_INFO items */
/* Typical use: If no callback is registered and an archive file is scanned, this list corresponds to each infected file found */
typedef struct _CLAM_SCAN_INFO_LIST
{
    /* Number of CLAM_SCAN_INFO structures present */
    int cbCount;

    /* Pointer to first CLAM_SCAN_INFO structure */
    PCLAM_SCAN_INFO pInfoList;
} CLAM_SCAN_INFO_LIST, *PCLAM_SCAN_INFO_LIST;



/**************************************************************************************
                                  CLAMAPI scan callback
***************************************************************************************/

/* SCAN CALLBACK ACTIONS */
/* The following actions can be requested by the scan callback */
typedef enum _CLAM_ACTION {
    CLAM_ACTION_CONTINUE, /* Keep on scanning */
    CLAM_ACTION_SKIP,     /* Skip the current file */
    CLAM_ACTION_ABORT     /* Early terminate the scan process */
} CLAM_ACTION;

/*
 * Callback that can be registered to be invoked by the scan engine on each inner file.
 * Parameters: 
 * INPUT @param pObjectInfo : all relevant information of the file being scanned
 * OUTPUT @param scanAction : action to be taken as determined by callback
 * INPUT @param context : any context to be passed to scan callback
 */
typedef void (CALL_CONVENTION *CLAM_SCAN_CALLBACK)(const CLAM_SCAN_INFO *pObjectInfo, CLAM_ACTION *scanAction, void *context);



/**************************************************************************************
                                    CLAMAPI functions
***************************************************************************************/

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
 * INPUT @param pTempRoot : path in which temporary files must be created
 * INPUT @param pLicenseKey : license key blob
 * INPUT @param bLoadMinDefs : load minimal defs
 */
int CLAMAPI Scan_Initialize(const wchar_t *pEnginesFolder, const wchar_t *pTempRoot, const wchar_t *pLicenseKey, BOOL bLoadMinDefs);

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
 * For archive, installers, compound files the callback should be invoked for each file. Each file can cause the callback to be invoked more than once.
 * INPUT @param pScanner : opaque object
 * INPUT @param pfnCallback : callback function
 * INPUT @param pContext : context to be passed to callback function
 */
int CLAMAPI Scan_SetScanCallback(CClamAVScanner *pScanner, CLAM_SCAN_CALLBACK pfnCallback, void *pContext);

/*
 * MANDATORY SUPPORT
 * Scan object using path
 * INPUT @param pScanner : opaque object
 * INPUT @param pObjectPath : path to object
 * OUTPUT @param pScanStatus : indicates status of scan (CLAM_CLEAN or CLAM_INFECTED)
 * OUTPUT @param pInfoList : list containing additional information about file that was scanned (ONLY valid in *pScanStatus == CLAM_INFECTED)
 */
int CLAMAPI Scan_ScanObject(CClamAVScanner *pScanner, const wchar_t *pObjectPath, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList);

/*
 * MANDATORY SUPPORT
 * Scan object using object handle
 * INPUT @param pScanner : opaque object
 * INPUT @param object : handle to object
 * OUTPUT @param pScanStatus : indicates status of scan
 * OUTPUT @param pInfoList : list containing additional information about file that was scanned (ONLY valid in *pScanStatus == CLAM_INFECTED)
 */
int CLAMAPI Scan_ScanObjectByHandle(CClamAVScanner *pScanner, HANDLE object, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList);

/*
 * Returns the outer file type as an _int64[2] for the give HANDLE
 * Scan is not performed and no callback is invoked
 * INPUT @param hFile : file handle whose type is to be determined
 * OUTPUT @param filetype : result array (_int64[2])
 */
 int CLAMAPI Scan_GetFileType(HANDLE hFile, _int64 *filetype);

/*
 * Checks if any meaningful signature is loaded
 * Returns 0 (false), 1 (true) or -1 (error)
 * OUTPUT @param official : set to the number of official signatures loaded, unless NULL
 * OUTPUT @param custom : set to the number of custom signatures loaded, unless NULL
 */
 int CLAMAPI Scan_HaveSigs(unsigned int *official, unsigned int *custom);

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
 * INPUT @param option : limit type
 * OUTPUT @param value : limit size in bytes
 */
int CLAMAPI Scan_GetLimit(int option, unsigned int *value);

/*
 * Set integer based scanning options
 * ex: scan Archives, scan packed samples, scan e-mail databases, scan installers
 * INPUT @param option : limit type
 * INPUT @param value : limit size in bytes
 */
int CLAMAPI Scan_SetLimit(int option, unsigned int value);

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

/* 
 * Convert a ClamAV error code into a string
 * INPUT @param errorCode
 * NOTE: the returned string is not to be freed!
 */
CLAMAPI const wchar_t * Scan_GetErrorMsg(int errorCode);

/*
 * Reload the virus database
 * INPUT @param bLoadMinDefs : full or minimal defininition selector
 */
CLAMAPI void Scan_ReloadDatabase(BOOL bLoadMinDefs);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _CLSCANAPI_H */
