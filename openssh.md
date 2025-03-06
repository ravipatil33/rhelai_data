Red Hat is the leading provider of enterprise open source software solutions. More than 90% of companies in the U.S. Fortune 500 continue to rely on Red Hat.

Enterprises around the world trust our broad portfolio of hybrid cloud infrastructure, application services, cloud-native application development, and automation solutions to deliver IT services on any infrastructure quickly and cost effectively.

Red Hat has several products in its portfolio.

1. Red Hat Enterprise Linux - Support application deployments—from on premise to the cloud to the edge—in a flexible operating environment.
2. Red Hat OpenShift - Quickly build and deploy applications at scale, while you modernize the ones you already have.
3. Red Hat Ansible Automation Platform - Create, manage, and dynamically scale automation across your entire enterprise.

Explore all Red Hat products by visiting https://www.redhat.com/en/technologies/all-products?intcmp=7013a000003Sl5EAAS

This document is for Common Vulnerabilities Exposures (CVEs) related to 'openssh' and other packages on RHEL platform, which is enterprise level, open source operating system by Red Hat. 

The openssh package is pre-installed on RHEL system. 

SSH (Secure SHell) is a program for logging into and executing commands on a remote machine. SSH is intended to replace rlogin and rsh, and to provide secure encrypted communications between two untrusted hosts over an insecure network. X11 connections and arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's version of the last free version of SSH, bringing it up to date in terms of security and features.

This package includes the core files necessary for both the OpenSSH client and server. To make this package useful, you should also install openssh-clients, openssh-server, or both.

This document is specifically created for details for following CVEs related to openssh package on RHEL 9. 

CVE-2023-48795
CVE-2023-51385
CVE-2024-6387
CVE-2024-6409
CVE-2024-7589

Lets dive deep into each of the vulnerabilities for more details. 

CVE-2023-48795

- The vulnerability or CVE CVE-2023-48795
 is also referred to as terrapin attack.
- This affects openssh packages on RHEL.

Description
A flaw was found in the SSH channel integrity. By manipulating sequence numbers during the handshake, an attacker can remove the initial messages on the secure channel without causing a MAC failure. For example, an attacker could disable the ping extension and thus disable the new countermeasure in OpenSSH 9.5 against keystroke timing attacks.

Statement
This CVE is classified as moderate because the attack requires an active Man-in-the-Middle (MITM) who can intercept and modify the connection's traffic at the TCP/IP layer.

Although the attack is cryptographically innovative, its security impact is fortunately quite limited. It only allows the deletion of consecutive messages, and deleting most messages at this protocol stage prevents user authentication from proceeding, leading to a stalled connection.

The most significant identified impact is that it enables a MITM to delete the SSH2_MSG_EXT_INFO message sent before authentication begins. This allows the attacker to disable a subset of keystroke timing obfuscation features. However, there is no other observable impact on session secrecy or session integrity.

Mitigation
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

For more details on using crypto-policies, please refer to https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening

Note that this procedure does limit the interoperability of the host and is only suggested as a temporary mitigation until the issue is fully resolved with an update.


