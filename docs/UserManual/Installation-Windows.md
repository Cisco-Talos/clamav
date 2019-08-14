# Installing ClamAV on Windows

If you wish to build ClamAV from source using Visual Studio 2015, please head over to the [Win32 ClamAV Build Instructions](win32/README.md) located in our source release materials on [ClamAV.net](https://www.clamav.net/downloads) and on [GitHub](https://github.com/Cisco-Talos/clamav-devel).

## Install using the ClamAV Windows Installer

Important: Installing ClamAV using the Installer will require Administrator privileges.

1. Download: http://www.clamav.net/downloads/production/ClamAV-0.101.4.exe
2. Locate the file in your Downloads directory.
3. Right-click on `ClamAV-0.101.4.exe` and select `Run as administrator`. You may receive a warning message along the lines of "Windows protected your PC".  Select `More info` and then select `Run anyway`.
4. Select `I accept the agreement` and click `Next`.
5. Click `Next` again. If you've removed a previous installation of ClamAV, you may receive the prompt "The folder ... already exists...". If you do, select `Yes`.
6. Click `Install`.
7. Click `Finish`.
8. Press the Windows-key and type `powershell` but _DO NOT_ press `Enter`. Right-click on `Windows PowerShell` at the top of the menu and select `Run as administrator`. Your computer may warn you `Do you want to allow this app to make changes to your device?`  Click `Yes`.
9. Verify that the prompt in the PowerShell window looks like this:
    ```powershell
    PS C:\WINDOWS\system32>
    ```

10. In the Adminstrator PowerShell window, enter the following to navigate to the ClamAV install directory:
    ```powershell
    cd "c:\program files\clamav"
    ```

Continue on to "First Time Set-Up" below...

## Install using the ClamAV Portable Install Package

1. Download: https://www.clamav.net/downloads/production/clamav-0.101.4-win-x64-portable.zip
2. Unzip it.
3. Open the `clamav-0.101.4-win-x64-portable` directory.
4. Hold down Shift and then right-click on the background in the current directory (but not on one of the files). Select `"Open PowerShell window here"`. If that option doesn't appear, try again.

Continue on to "First Time Set-Up"...

## First Time Set-Up

In the PowerShell window, perform the following tasks:

* Run:
    ```powershell
    copy .\conf_examples\freshclam.conf.sample .\freshclam.conf
    ```
* Run:
    ```powershell
    write.exe .\freshclam.conf
    ```
* WordPad will pop up. Delete the line that says "Example". Save the file and close WordPad.

## Next Steps

### Download the Signature Databases

Before you can start the ClamAV scanning engine (using either `clamd` or `clamscan`), you must _first_ have ClamAV Virus Database (.cvd) file(s) installed in the appropriate location on your system. The default location for these database files is C:\Program Files\ClamAV\database, the database directory of your ` (in Windows).

Continuing in the PowerShell window:

1. Run:
    ```powershell
    .\freshclam.exe
    ```
2. freshclam will download some files and drop them in the database directory. This can take a minute or two depending on how fast your internet connection is. The files are a pretty large.
3. You are now ready to perform scans with ClamAV. If you using the portable install package, you may now copy the entire `clamav-0.100.1-win-x64-portable` directory to the computer(s) you wish to scan.

### Steps to Perform Basic Scanning

* Run this to scan the files in the current directory:
    ```powershell
    .\clamscan.exe .
    ```

  This will scan the current directory. At the end of the scan, it will display a summary. If you notice in the clamscan output, it only scanned something like 60 files, even though there are more files in subdirectories. By default, clamscan will only scan files in the current directory.

* Run this to scan all the files in the current directory:
    ```powershell
    .\clamscan.exe --recursive .
    ```

* Run this to scan ALL the files on your C: drive, it will take **quite** a while. Keep in mind that you can cancel it at any time by pressing `Ctrl-C`:
    ```powershell
    .\clamscan --recursive C:\
    ```

* For more information on ways you can use clamscan, run:
    ```powershell
    .\clamscan.exe --help
    ```

### Faster a-la-carte Scanning with `clamd`

You may have noticed that `clamscan` takes a while to get started. This is because it loads the signature database each time you start a scan. If you require faster scanning of individual files, you will want to use `clamd` with `clamdscan` instead.

Continuing in the PowerShell window:

1. Run:
    ```powershell
    .\clamd.exe
    ```
    The application will take a moment to load and then appear to hang, but it is in fact waiting for scanning commands from `clamdscan`.
2. Open a second PowerShell window as you did above, in the same directory.
3. In the second PowerShell window, you can now run `clamdscan` much the same way you did with `clamscan` above.
    ```powershell
    .\clamdscan.exe .
    ```
