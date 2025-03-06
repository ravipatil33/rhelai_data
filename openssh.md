# Red Hat openssh Vulnerabilities 

Red Hat is the leading provider of enterprise open source software solutions. More than 90% of companies in the U.S. Fortune 500 continue to rely on Red Hat.

Enterprises around the world trust our broad portfolio of hybrid cloud infrastructure, application services, cloud-native application development, and automation solutions to deliver IT services on any infrastructure quickly and cost effectively.

Red Hat has several products in its portfolio.

1. Red Hat Enterprise Linux - Support application deployments—from on premise to the cloud to the edge—in a flexible operating environment.
2. Red Hat OpenShift - Quickly build and deploy applications at scale, while you modernize the ones you already have.
3. Red Hat Ansible Automation Platform - Create, manage, and dynamically scale automation across your entire enterprise.

Explore all Red Hat products by visiting [Red Hat Products](https://www.redhat.com/en/technologies/all-products?intcmp=7013a000003Sl5EAAS)

This document is for Common Vulnerabilities Exposures (CVEs) related to 'openssh' and other packages on RHEL platform, which is enterprise level, open source operating system by Red Hat. 

The openssh package is pre-installed on RHEL system. 

SSH (Secure SHell) is a program for logging into and executing commands on a remote machine. SSH is intended to replace rlogin and rsh, and to provide secure encrypted communications between two untrusted hosts over an insecure network. X11 connections and arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's version of the last free version of SSH, bringing it up to date in terms of security and features.

This package includes the core files necessary for both the OpenSSH client and server. To make this package useful, you should also install openssh-clients, openssh-server, or both.

## CVEs covered in this document 

This document is specifically created for details for following CVEs related to openssh package on RHEL 9. 

CVE-2023-48795<br>
CVE-2023-51385<br>
CVE-2024-6387<br>
CVE-2024-6409<br>
CVE-2024-7589<br>

Lets dive deep into each of the vulnerabilities for more details. 

## 1. CVE-2023-48795

- The vulnerability or CVE CVE-2023-48795
 is also referred to as terrapin attack.
- This affects openssh packages on RHEL.

### Description
A flaw was found in the SSH channel integrity. By manipulating sequence numbers during the handshake, an attacker can remove the initial messages on the secure channel without causing a MAC failure. For example, an attacker could disable the ping extension and thus disable the new countermeasure in OpenSSH 9.5 against keystroke timing attacks.

### Statement
This CVE is classified as moderate because the attack requires an active Man-in-the-Middle (MITM) who can intercept and modify the connection's traffic at the TCP/IP layer.

Although the attack is cryptographically innovative, its security impact is fortunately quite limited. It only allows the deletion of consecutive messages, and deleting most messages at this protocol stage prevents user authentication from proceeding, leading to a stalled connection.

The most significant identified impact is that it enables a MITM to delete the SSH2_MSG_EXT_INFO message sent before authentication begins. This allows the attacker to disable a subset of keystroke timing obfuscation features. However, there is no other observable impact on session secrecy or session integrity.

### Mitigation
Update to the last version and check that client and server provide kex pseudo-algorithms indicating usage of the updated version of the protocol which is protected from the attack. If "kex-strict-c-v00@openssh.com" is provided by clients and "kex-strict-s-v00@openssh.com" is in the server's reply, no other steps are necessary.

Disabling ciphers if necessary:

If "kex-strict-c-v00@openssh.com" is not provided by clients or "kex-strict-s-v00@openssh.com" is absent in the server's reply, you can disable the following ciphers and HMACs as a workaround on RHEL-8 and RHEL-9:

1. chacha20-poly1305@openssh.com
2. hmac-sha2-512-etm@openssh.com
3. hmac-sha2-256-etm@openssh.com
4. hmac-sha1-etm@openssh.com
5. hmac-md5-etm@openssh.com

To do that through crypto-policies, one can apply a subpolicy with the following content:

cipher@SSH = -CHACHA20-POLY1305
ssh_etm = 0
e.g., by putting these lines into `/etc/crypto-policies/policies/modules/CVE-2023-48795.pmod`, applying the resulting subpolicy with `update-crypto-policies --set $(update-crypto-policies --show):CVE-2023-48795` and restarting openssh server.
One can verify that the changes are in effect by ensuring the ciphers listed above are missing from both `/etc/crypto-policies/back-ends/openssh.config` and `/etc/crypto-policies/back-ends/opensshserver.config`.

For more details on using crypto-policies, please refer to [System wide cryptographic policies in RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening)

Note that this procedure does limit the interoperability of the host and is only suggested as a temporary mitigation until the issue is fully resolved with an update.

### Solution 
Fix for CVE-2023-48795 is released as 	RHSA-2024:1130 on 5th March 2024. For details on fix refer errata link [RHSA-2024:1130](https://access.redhat.com/errata/RHSA-2024:1130)

To fix vulnerability, update the openssh package to version 8.7p1-34.el9_3.3.x86_64. 

The errata details are available on [RHSA-2024:1130](https://access.redhat.com/errata/RHSA-2024:1130) referred as RHSA-2024:1130 in short. 

### CVSS v3 Score Breakdown
|  | Red Hat | NVD |
| --- | --- | --- |
| CVSS v3 Base Score | 5.9 | 5.9 |
| Attack Vector | Network | Network |
| Attack Complexity | High | High |
| Privileges Required | None | None |
| User Interaction | None | None |
| Scope | Unchanged | Unchanged |
| Confidentiality Impact | None | None |
| Integrity Impact | High | High |
| Availability Impact | None | None |

## RHSA-2024:1130

### Synopsis
Moderate: openssh security update

### Type/Severity
Security Advisory: Moderate

An update for openssh is now available for Red Hat Enterprise Linux 9.

OpenSSH is an SSH protocol implementation supported by a number of Linux, UNIX, and similar operating systems. It includes the core files necessary for both the OpenSSH client and server.

### Security Fix(es):

ssh: Prefix truncation attack on Binary Packet Protocol (BPP) (CVE-2023-48795)
openssh: potential command injection via shell metacharacters (CVE-2023-51385)

CVEs fixed by RHSA-2024:1130 includes following two CVEs : 
CVE-2023-48795
CVE-2023-51385

To install or update the packages, there are two ways, either using 'dnf' utility or by manually downloading the packages from package browser link for [package browser](https://access.redhat.com/downloads/content/package-browser) and using rpm to install or update the package. 


## Backporting security fixes
- Red Hat use the term backporting to describe when it takes a fix for a security flaw out of the most recent version of an upstream software package, and applies that fix to an older version of the package distributed by Red Hat.
- Backporting has a number of advantages, but it can create confusion when it is not understood.  For example, stories in the press may include phrases such as "upgrade to Apache httpd 2.0.43 to fix the issue", which only takes into account the upstream version number. This can cause confusion as even after installing updated packages from a vendor, it is not likely to have the latest upstream version, but rather have an older upstream version with backported patches applied.

- Also, some security scanning and auditing tools make decisions about vulnerabilities based solely on the version number of components they find. This results in false positives as the tools do not take into account backported security fixes.

For details on [security issues flagged by Nessus reveals false positives](https://access.redhat.com/solutions/486883)
