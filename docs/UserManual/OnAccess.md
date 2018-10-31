# On-Access Scanning

---

## Purpose

---

This guide is for users interested in leveraging and understanding ClamAV's On-Access Scanning feature. It will walk through how to set up and use the On-Access Scanner and step through some common issues and their solutions.

---

## Requirements

---

On-Access is only available on Linux systems. On Linux, On-Access requires a `kernel version >= 3.8`. This is because it leverages a kernel api called [fanotify](http://man7.org/linux/man-pages/man7/fanotify.7.html) to perform its blocking.

---

## General Use

---

To use ClamAV's On-Access Scanner, simply open `clamd.conf`, set the `ScanOnAccess` option to `yes`, and then specify the path(s) you would like to recursively watch with the `OnAccessIncludePath` option. Finally, set `OnAccessPrevention` to `yes`. Then, run `clamd` with elevated permissions (e.g. `sudo clamd`). If all went well, the On-Access scanner will now be actively protecting the specified path(s). You can test this by dropping an eicar file into the specified path, and attempting to read/access it (e.g. `cat eicar.txt`). This will result in an "Operation not permitted" message, triggered by fanotify blocking the access attempt at the kernel level.

---

## Troubleshooting
---

Some OS distributors have disabled fanotify, despite kernel support. You can check for fanotify support on your kernel by running the command:

> $ cat /boot/config-<kernel_version> | grep FANOTIFY

You should see the following:

```
CONFIG_FANOTIFY=y
CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y
```

If you see:

```
# CONFIG_FANOTIFY_ACCESS_PERMISSIONS is not set
```

Then ClamAV's On-Access Scanner will still function, scanning and alerting on files normally in real time. However, it will be unable to block access attempts on malicious files. We call this `notify-only` mode.

---

ClamAV's On-Access Scanning system uses a scheme called Dynamic Directory Determination (DDD for short) which is a shorthand way of saying that it tracks the layout of every directory specified with `OnAccessIncludePath` dynamically, and recursively, in real time. It does this by leveraging [inotify](http://man7.org/linux/man-pages/man7/inotify.7.html) which by default has a limited number of watchpoints available for use by a process at any given time. Given the complexity of some directory hierarchies, ClamAV may warn you that it has exhausted its supply of inotify watchpoints (8192 by default). To increase the number of inotify watchpoints available for use by ClamAV (to 524288), run the following command:

> $ echo 524288 | sudo tee -a /proc/sys/fs/inotify/max_user_watches

---

The `OnAccessIncludePath` option will not accept `/` as a valid path. This is because fanotify works by blocking a process' access to a file until a access_ok or access_denied determination has been made by the original fanotify calling process. Thus, by placing fanotify watchpoints on the entire filesystem, key system files may have their access blocked at the kernel level, which will result in a system lockup.

This restriction was made to prevent users from "shooting themselves in the foot." However, clever users will find it's possible to circumvent this restriction by using multiple `OnAccessIncludePath` options to protect most all the filesystem anyways, or simply the paths they truly care about.

---

The `OnAccessMountPath` option uses a different fanotify api configuration which makes it incompatible with `OnAccessIncludePath` and the DDD System. Therefore, inotify will not be a concern when using this option. Unfortunately, this also means `OnAccessExtraScanning` (which is built around catching inotify events), and `OnAccessExcludePath` (which is built upon the DDD System) cannot be used in conjunction with `OnAccessMountPath`.

---

## Configuration and Recipes

---

More nuanced behavior can be coerced from ClamAV's On-Access Scanner via careful modification to `clamd.conf`. Each option related to On-Access Scanning is easily identified by looking for the `OnAccess` prefix pre-pended to each option. The default `clamd.conf` file contains descriptions of each option, along with any documented limitations or safety features.

Below are examples of common use cases, recipes for the correct minimal configuration, and the expected behavioral result.

---

#### Use Case 0x0
  - User needs to watch the entire file system, but blocking malicious access attempts isn't a concern
  ```
  ScanOnAccess yes
  OnAccessMountPath /
  OnAccessExcludeRootUID yes
  ```

  This configuration will put the On-Access Scanner into `notify-only` mode. It will also ensure only non-root, non-clam, user processes will trigger scans against the filesystem.

---

#### Use Case 0x1
  - System Administrator needs to watch the home directory of multiple Users, but not all users. Blocking access attempts is un-needed.
  ```
  ScanOnAccess yes
  OnAccessIncludePath /home
  OnAccessExcludePath /home/user2
  OnAccessExcludePath /home/user4
  ```

  With this configuration, the On-Access Scanner will watch the entirety of the `/home` directory recursively in `notify-only` mode. However, it will recursively exclude the `/home/user2` and `/home/user4` directories.

---

#### Use Case 0x2
  - The user needs to protect a single directory non-recursively and ensure all access attempts on malicious files are blocked.
  ```
  ScanOnAccess yes
  OnAccessIncludePath /home/user/Downloads
  OnAccessPrevention yes
  OnAccessDisableDDD yes
  ```

  The configuration above will result in non-recursive real-time protection of the `/home/user/Downloads` directory by ClamAV's On-Access Scanner. Any access attempts that ClamAV detects on malicious files within the top level of the directory hierarchy will be blocked by fanotify at the kernel level.

---
