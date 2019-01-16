# Usage

---

<!-- TOC depthFrom:2 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [Usage](#usage)
  - [Purpose](#purpose)
  - [Daemon](#daemon)
  - [Scanner](#scanner)
  - [Signature Testing and Management](#signature-testing-and-management)
  - [Configuration](#configuration)

<!-- /TOC -->

---

## Purpose

---

This User Guide presents an overview of the various ways that *libclamav* can be used through the tools provided by ClamAV. To learn more about how to better use each facet of ClamAV that interests you, please follow the links provided.

---

## Daemon

---

The ClamAV Daemon, or [`clamd`](Usage/Scanning.md#clamd), is a multi-threaded daemon that uses *libclamav* to [scan files for viruses](Usage/Scanning.md). ClamAV provides a number of tools which interface with this daemon. They are, as follows:

  - [`clamdscan`](Usage/Scanning.md#clamdscan) - a simple scanning client
  - [`on-access scanning`](Usage/Scanning.md#On-access-scanning) - provides real-time protection via a `clamd` instance
  - [`clamdtop`](Usage/Scanning.md#clamdtop) - a resource monitoring interface for `clamd`

---

## Scanner

---

ClamAV also provides a command-line tool for [simple scanning](Usage/Scanning.md) tasks with *libclamav* called [`clamscan`](Usage/Scanning.md#clamscan). Unlike the daemon, `clamscan` is not a persistent process and is best suited for use cases where one-time scanning with minimal setup is needed.

---

## Signature Testing and Management

---

A number of tools allow for [testing and management of signatures](Usage/SignatureManagement.md). Of note are the following:

  - [`clambc`](Usage/SignatureManagement.md#clambc) - specifically for testing bytecode
  - [`sigtool`](Usage/SignatureManagement.md#sigtool) - for general signature testing and analysis
  - [`freshclam`](Usage/SignatureManagement.md#freshclam) - used to update signature database sets to the latest version

---

## Configuration

---

The more complex tools ClamAV provides each require some degree of [configuration](Usage/Configuration.md). ClamAV supplies two example configuration files:

  - [`clamd.conf`](Usage/Configuration.md#clamdconf) - for configuring the behaviour of the ClamAV Daemon `clamd` and associated tools
  - [`freschclam.conf`](Usage/Configuration.md#freshclamconf) - for configuring the behaviour of the signature database update tool, `freshclam`

ClamAV also provides a mail filtering tool called [`clamav-milter`](Usage/Configuration.md#clamav-milter) which can be attached to a `clamd` instance for mail scanning purposes.

Additionally, a tool called [`clamconf`](Usage/Configuration.md#clamconf) allows users to check the configurations used by each other tool, pulling information from the configuration files listed above, alongside other relevant information.
