# Signature Testing and Management

---

<!-- TOC depthFrom:2 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [freshclam](#freshclam)
- [sigtool](#sigtool)
- [clambc](#clambc)

<!-- /TOC -->

---

## freshclam

---

The tool `freshclam` is used to download and update ClamAV’s official virus signature databases. While easy to use in its base configuration, `freshclam` does require a working [`freshclam.conf` configuration file](Configuration.md#freshclam) to run (the location of which can be passed in via command line if the default search location does not fit your needs).

Once you have a valid configuration file, you can invoke freshclam with the following command:

> $ freshclam

By default, `freshclam` will then attempt to connect to ClamAV's virus signature database distribution network. If no databases exist in the directory specified, `freshclam` will do a fresh download of the requested databases. Otherwise, `freshclam` will attempt to update existing databases, pairing them against downloaded cdiffs. If a database is found to be corrupted, it is not updated and instead replaced with a fresh download.

Of course, all this behaviour--and more--can be changed to suit your needs by [modifying `freshclam.conf` and/or using various command line options](Configuration.md#freshclamconf).

You can find more information about freshclam with the commands:

> $ `man freshclam`

and

> $ `freshclam --help`

---

## sigtool

---

ClamAV provides `sigtool` as a command-line testing tool for assisting users in their efforts creating and working with virus signatures. While sigtool has many uses--including crafting signatures--of particular note, is sigtool's ability to help users and analysts in determining if a file detected by *libclamav*'s virus signatures is a false positive.

This can be accomplished by using the command:

> $ `sigtool --unpack=FILE`

Where FILE points to your virus signature databases. Then, once `sigtool` has finished unpacking the database into the directory from which you ran the command, you can search for the offending signature name (provided either by [`clamscan`](./Scanning.md#clamscan) scan reports or [`clamd`](./Scanning.md#clamd) logs). As an example:

> $ `grep "Win.Test.EICAR" ./*`

Or, do all that in one step with:

> $ `sigtool --find="Win.Test.EICAR"`

This should give you the offending signature(s) in question, which can then be included as part of your [false positive report](https://www.clamav.net/reports/fp).

To learn more in depth information on how `sigtool` can be used to help create virus signatures and work with malicious (and non-malicious) files please reference the many online tutorials on the topic.

Otherwise, information on available sigtool functions can be easily referenced with:

> $ `sigtool --help`

and

> $ `man sigtool`

---

## clambc

---

`clambc` is Clam Anti-Virus’ bytecode signature testing tool. It can be used to test newly crafted bytecode signatures or to help verify existing bytecode is executing against a sample as expected.

For more detailed help, please use:

> $ `man clambc`

or

> $ `clambc --help`
