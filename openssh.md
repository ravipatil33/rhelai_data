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

| Product | Components | State | Errata 
| --- | --- | --- | --- |
| Red Hat Enterprise Linux 9 | openssh | Fixed |		RHSA-2024:1130
| Red Hat Enterprise Linux 9 | libssh | Fixed |		RHBA-2024:1127

To fix vulnerability, update the openssh package to version 8.7p1-34.el9_3.3.x86_64. 
$ dnf update openssh*

The errata details are available on [RHSA-2024:1130](https://access.redhat.com/errata/RHSA-2024:1130) referred as RHSA-2024:1130 in short. 

For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

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

## CVE-2023-51385

- This affects openssh packages on RHEL.
- A remote attacker may be able to execute arbitrary OS commands by using expansion tokens, such as %u or %h

### Description
A flaw was found in OpenSSH. In certain circumstances, a remote attacker may be able to execute arbitrary OS commands by using expansion tokens, such as %u or %h, with user names or host names that contain shell metacharacters.

### Statement
The ability to execute OS commands is dependent on what quoting is present in the user-supplied ssh_config directive. However, it is generally the user's responsibility to validate arguments passed to SSH.

### Mitigation
Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base or stability.

### Solution 
Fix for CVE-2023-51385 is released as RHSA-2024:1130 on 5th March 2024. For details on fix refer errata link [RHSA-2024:1130](https://access.redhat.com/errata/RHSA-2024:1130)
| Product | Components | State | Errata 
| --- | --- | --- | --- |
| Red Hat Enterprise Linux 9 | openssh | Fixed |		RHSA-2024:1130

To fix vulnerability, update the openssh package to version 8.7p1-34.el9_3.3.x86_64. 
$ dnf update openssh*

The errata details are available on [RHSA-2024:1130](https://access.redhat.com/errata/RHSA-2024:1130) referred as RHSA-2024:1130 in short. 

This errata RHSA-2024:1130 fixes two vulnerabilities : 
CVE-2023-48795
CVE-2023-51385

## CVE-2024-6387

- This affects openssh packages on RHEL.
- A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd).

### Description
A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

### Statement
Red Hat rates the severity of this flaw as Important for both Red Hat Enterprise Linux (RHEL) and OpenShift Container Platform (OCP). The most significant risk is Remote Code Execution, however this outcome requires significant resources to exploit. If mitigations are put in place, the consequences of exploitation are reduced. An attacker would then only be able to impact availability of the OpenSSH service.

The main factor preventing a higher impact rating is an unpredictable race condition. All actively supported versions of RHEL (and by extension OCP) have ExecShield (aka ASLR) enabled by default and utilize NX technology, reducing reliability of the attack. Attackers are forced to retry the attack thousands of times. This generates significant noise providing defenders with an opportunity to detect and disrupt potential attacks.

RHEL 9 is the only affected version. RHEL 6, 7, and 8 all utilize an older version of OpenSSH which was never affected by this vulnerability.

### Mitigation
The below process can protect against a Remote Code Execution attack by disabling the LoginGraceTime parameter on Red Hat Enterprise Linux 9. However, the sshd server is still vulnerable to a Denial of Service if an attacker exhausts all the connections.

1) As root user, open the /etc/ssh/sshd_config
2) Add or edit the parameter configuration:
$ vi /etc/ssh/sshd_config
LoginGraceTime 0
3) Save and close the file
4) Restart the sshd daemon:
$ systemctl restart sshd.service
Setting LoginGraceTime to 0 disables the SSHD server's ability to drop connections if authentication is not completed within the specified timeout. If this mitigation is implemented, it is highly recommended to use a tool like 'fail2ban' alongside a firewall to monitor log files and manage connections appropriately.

If any of the mitigations mentioned above is used, please note that the removal of LoginGraceTime parameter from sshd_config is not automatic when the updated package is installed.

### Solution

The fix for CVE-2024-6387 has been released as [RHSA-2024:4312](https://access.redhat.com/errata/RHSA-2024:4312) and vulnerability if fixed in openssh version 8.7p1-38.el9_4.1.x86_64.
| Product | Components | State | Errata 
| --- | --- | --- | --- |
| Red Hat Enterprise Linux 9 | openssh | Fixed |		RHSA-2024:4312

To fix vulnerability, update openssh package to version 8.7p1-38.el9_4.1.x86_64.rpm or higher. If already on higher version, you are not affected by the vulnerability. 

$ dnf update openssh*

For details refer RHSA link [RHSA-2024:4312](https://access.redhat.com/errata/RHSA-2024:4312).

For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

### CVSS v3 Score Breakdown
|  | Red Hat | NVD |
| --- | --- | --- |
| CVSS v3 Base Score | 8.1 | 8.1 |
| Attack Vector | Network | Network |
| Attack Complexity | High | High |
| Privileges Required | None | None |
| User Interaction | None | None |
| Scope | Unchanged | Unchanged |
| Confidentiality Impact | High | High |
| Integrity Impact | High | High |
| Availability Impact | High | High |

## RHSA-2024:4312

### Synopsis
Important: openssh security update

### Type/Severity
Security Advisory: Important

### Description 
An update for openssh is now available for Red Hat Enterprise Linux 9.

OpenSSH is an SSH protocol implementation supported by a number of Linux, UNIX, and similar operating systems. It includes the core files necessary for both the OpenSSH client and server.

### Security Fix(es):

openssh: Possible remote code execution due to a race condition in signal handling (CVE-2024-6387)

### CVEs
CVE-2024-6387

## CVE-2024-6409

- This affects openssh packages on RHEL.
- A race condition vulnerability was discovered in how signals are handled by OpenSSH's server (sshd)

### Description
A race condition vulnerability was discovered in how signals are handled by OpenSSH's server (sshd). If a remote attacker does not authenticate within a set time period, then sshd's SIGALRM handler is called asynchronously. However, this signal handler calls various functions that are not async-signal-safe, for example, syslog(). As a consequence of a successful attack, in the worst case scenario, an attacker may be able to perform a remote code execution (RCE) as an unprivileged user running the sshd server.

### Statement
Red Hat rates the severity of this flaw as Moderate for both Red Hat Enterprise Linux (RHEL) and OpenShift Container Platform (OCP). While there are many similarities to CVE-2024-6387, the important difference is that any possible remote code execution is limited to an unprivileged child of the SSHD server. This additional restriction on access reduces the overall security impact.

This vulnerability only affects the versions of OpenSSH shipped with Red Hat Enterprise Linux 9. Upstream versions of sshd are not impacted by this flaw.

### Mitigation
The process is identical to CVE-2024-6387, by disabling LoginGraceTime. See that CVE page for additional details.

### Solution 
The fix for CVE-2024-6409 has been released as [RHSA-2024:4457](https://access.redhat.com/errata/RHSA-2024:4457) and vulnerability if fixed in openssh version 8.7p1-38.el9_4.4.x86_64.
| Product | Components | State | Errata 
| --- | --- | --- | --- |
| Red Hat Enterprise Linux 9 | openssh | Fixed |	RHSA-2024:4457

To fix vulnerability, update openssh package to version 8.7p1-38.el9_4.4.x86_64 or higher. If already on higher version, you are not affected by the vulnerability. 

$ dnf update openssh*

For details refer RHSA link [RHSA-2024:4457](https://access.redhat.com/errata/RHSA-2024:4457) 

For details on how to apply this update, which includes the changes described in this advisory, refer to:

https://access.redhat.com/articles/11258

## RHSA-2024:4457

### Synopsis
Moderate: openssh security update

### Type/Severity
Security Advisory: Moderate

An update for openssh is now available for Red Hat Enterprise Linux 9.

### Security Fix(es):

openssh: Possible remote code execution due to a race condition in signal handling affecting Red Hat Enterprise Linux 9 (CVE-2024-6409)

### CVEs
CVE-2024-6409

## CVE-2024-7589

- This does not affect openssh packages on RHEL.
- This vulnerability is specific to the FreeBSD distribution of OpenSSH.

### Description
A signal handler in sshd(8) may call a logging function that is not async-signal-safe. The signal handler is invoked when a client does not authenticate within the LoginGraceTime seconds (120 by default). This signal handler executes in the context of the sshd(8)'s privileged code, which is not sandboxed and runs with full root privileges. This issue is another instance of the problem in CVE-2024-6387 addressed by FreeBSD-SA-24:04.openssh. The faulty code in this case is from the integration of blacklistd in OpenSSH in FreeBSD. As a result of calling functions that are not async-signal-safe in the privileged sshd(8) context, a race condition exists that a determined attacker may be able to exploit to allow an unauthenticated remote code execution as root.

### Statement
This vulnerability is specific to the FreeBSD distribution of OpenSSH. Red Hat Products are not affected.

### Mitigation
As this does not affect openssh package on RHEL, there is no mitigation applicable. 

### Solution 
There is no action required as this vulnerability is specific to the FreeBSD distribution of OpenSSH. Red Hat Products are not affected.
| Product | Components | State | Errata 
| --- | --- | --- | --- |
| Red Hat Enterprise Linux 9 | openssh | Not affected	 | N/A 

## Configuration vulnerabilities in openssh

### SSH Server Supports Weak Key Exchange Algorithms

The diffie-hellman-group1-sha1 key exchange algorithm is already disabled in DEFAULT system-wide cryptographic policy in Red Hat Enterprise Linux 8 and 9.
For more details, read this solution:
[Steps to disable the diffie-hellman-group1-sha1 algorithm in SSH](https://access.redhat.com/solutions/4278651)

### SSH CBC Mode Ciphers Enabled

To remove the CBC algorithm from the server for sshd, modify ssh_cipher in /etc/crypto-policies/policies/modules/DISABLE-CBC.pmod for Red Hat Enterprise Linux 8 and 9:

ssh_cipher = -AES-128-CBC -AES-256-CBC
Once done, apply the new policy:

# sudo update-crypto-policies --set DEFAULT:DISABLE-CBC
For more details, read this solution:

[How to disable specific crypto algorithms when using system-wide cryptographic policies](https://access.redhat.com/articles/7041246)

### SSH Insecure HMAC Algorithms Enabled
The diffie-hellman-group1-sha1 key exchange algorithm is already disabled in DEFAULT system-wide cryptographic policy in Red Hat Enterprise Linux 8 and 9.
For more details, read this solution:

[Steps to disable the diffie-hellman-group1-sha1 algorithms in SSH](https://access.redhat.com/solutions/4278651)

### Terrapin Attack (CVE-2023-48795)

You can disable the following ciphers and HMACs as a workaround on Red Hat Enterprise Linux 8 and 9:

chacha20-poly1305@openssh.com
hmac-sha2-512-etm@openssh.com
hmac-sha2-256-etm@openssh.com
hmac-sha1-etm@openssh.com
hmac-md5-etm@openssh.com

To do that through crypto-policies, put these lines into `/etc/crypto-policies/policies/modules/CVE-2023-48795.pmod`:/

cipher@SSH = -CHACHA20-POLY1305
ssh_etm = 0
Once done, apply the new policy:

$ sudo update-crypto-policies --set $(update-crypto-policies --show):CVE-2023-48795
One can verify that the changes are in effect by ensuring the ciphers listed above are missing from both `/etc/crypto-policies/back-ends/openssh.config` and `/etc/crypto-policies/back-ends/opensshserver.config`.

### Validation
To list all supported ciphers by ssh server, there are two alternatives as below :

1. Using nmap
# nmap --script ssh2-enum-algos -sV -p 22 127.0.0.1
This command lists supported algorithms including key exchange,encryption, MAC, compression algorithms

2. Using sshd command utility
# sshd -T | egrep "cipher|mac|kexalgorithm"
