# ClamAV Security Policy

## What constitutes a security issue / vulnerability?

A security issue, or vulnerability, may be any bug that represents a threat to the security of the ClamAV users or any issue that a malicious person could use to cause a Denial of Service (DoS) attack on a network service running ClamAV, such as a mail filter or file upload scanner.

This definition includes issues where untrusted user input such as scanning a file or loading a signature database`*` may cause a severe memory leak, cause a crash, cause an infinite loop, or provide any other means to impair or disable ClamAV.

A vulnerability also includes all other traditional security vectors such as privilege escalation, remote code execution, information disclosure, etc.

If you are unsure if your bug is a security issue, please report it as a security issue.

> `*`Bytecode signatures are cross-platform executable plugins. ClamAV will not load bytecode signatures unless they are signed by Cisco-Talos or the user has intentionally enabled unsigned bytecode signatures. Issues that require disabling this security mechanism and then loading unsigned bytecode signatures or loading unsigned bytecode signatures with the ClamBC signature testing tool are not considered to be vulnerabilities.

## Vulnerability reporting best practices.

Do **not** discuss the issue in a public forum, the project mailing lists, in chat, or anywhere else.

Do **not** create a ticket on GitHub Issues. GitHub Issues are public. Submitting any information there on how to exploit ClamAV puts the ClamAV community at risk. If you do report a vulnerability via GitHub issues, your issue will be promptly removed.

Submit your report by email to psirt@cisco.com. Support requests submitted to Cisco PSIRT that are received via email are typically acknowledged within 48 hours. PSIRT will provide you with additional information on how to proceed. Cisco PSIRT will work with the ClamAV developers to confirm or reject the security vulnerability.

If the report is rejected, PSIRT or the ClamAV developers will write to you to explain why.

If the report is accepted, the ClamAV team will craft a fix and may request your help to verify that you find it satisfactory. Cisco will assign a CVE ID and will work with you to identify a disclosure date when the CVE summary will become public and when it will be safe to discuss in public.

Please allow us at least 90 days (about 3 months) to craft a fix and publish a security patch version with the fix before you tell anyone else about it. This non-disclosure window is critical to the security of your fellow ClamAV users and to the security of other products using libclamav.

## How do I submit my vulnerability report?

Security issues should be reported to Cisco PSIRT. The recommended method is to submit in email form to psirt@cisco.com. For details, see: https://tools.cisco.com/security/center/resources/security_vulnerability_policy.html

## What should I include in my vulnerability report?

Follow the same best practices for reporting a regular bug, but do not submit it on GitHub Issues! Instead, craft an email with the detailed report and attached files and submit it to psirt@cisco.com.

First, verify that the bug exists in the latest stable patch release. This may not be the latest release provided by your package manager.

At a minimum include the following:

- Include step-by-step instructions for how to reproduce the issue.

- If the issue is triggered by scanning a specific file, either:

  - Include the file in an encrypted zip along with the password.

  - Include instructions for how to generate a file that can be used to reproduce the issue.

- Describe your working environment:

  - Use the `clamconf` tool provided with ClamAV to describe your configuration. The `clamconf` tool will include operating system name, version, architecture, configuration information, etc. If you cannot use `clamconf`, describe this information in your report by hand.

  - If you found the bug using a fuzzer or some other system, describe the system and provide instructions for how we can reproduce the issue using the same or similar tools.

- If you are reporting a crash when scanning a file with ClamScan or ClamD, include a backtrace. See below for instructions on how to obtain a crash backtrace.

## How to obtain a crash backtrace.

When reporting a crash, please send us the backtrace obtained from `gdb`, the GNU Project Debugger, if possible. Here are step by step instructions which will guide you through the process.

### ClamScan

Assuming you get something like this, then you can use these instructions to help collect a backtrace for the report:
```bash
clamscan --some-options some_file

Segmentation fault
```

1. Have the kernel write a core dump.

    For bourne-like shells (e.g. bash):
    ```bash
    ulimit -c unlimited
    ```

    For C-like shells (e.g. tcsh):

    ```sh
    limit coredumpsize unlimited
    ```

2. Now you should see the core dumped message:
    ```bash
    clamscan --some-options some_file

    Segmentation fault (core dumped)
    ```

    Looking at your current working directory should reveal a file named core.

3. Load the core file into gdb:
    ```bash
    gdb -core=core --args clamscan --some-options some_file
    ```

    You should now see the gdb prompt, as: `(gdb)`

4. Just use the `bt` command at the prompt to make gdb print a full backtrace. Copy and paste it into the bug report. You can use the `q` command to leave gdb.

### ClamD

Follow these instructions to attach gdb to a running ClamD process so you can record a crash backtrace.

1. Use `ps` to get the PID of ClamD (first number from the left):
    ```bash
    ps -aux (or ps -elf on SysV)

    clamav 24897 0.0 1.9 38032 10068 ? S Jan13 0:00 clamd
    ```

2. Attach gdb to the running process. *Replace `24897` with the pid of ClamD and adjust the path of ClamD as needed*:
    ```bash
    gdb /usr/sbin/clamd 24897
    ```

    You should now get the gdb prompt, as: `(gdb)`

3. If you want ClamD to continue running (i.e. until a segmentation fault occurs), issue the `continue gdb` command. Then perform the commands to trigger the crash (like scanning a specific file with ClamDScan).

4. When the crash occurs, gdb will return to its prompt. As with the ClamScan instructions, use the `bt` command at the prompt to make gdb print a full backtrace. Copy and paste it into the bug report. You can use the `q` command to leave gdb.

### GDB Commands

- `bt` - will give a backtrace for the current thread.

- `info threads` - will tell you how many threads there are.

- `thread n` - will change to the specified thread, after which you can use the bt command again to get it’s backtrace.

So, you basically want to use `info threads` to get the number of threads and their id numbers; and for each thread do `thread id_number`; then `bt`. Exit from gdb with the `quit` command. Reply `y` to the question about the program still running.
