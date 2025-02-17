{
  "SchemaVersion": 2,
  "CreatedAt": "2025-02-15T03:57:24.159860051Z",
  "ArtifactName": "maheshecrregistry.azurecr.io/maheshnginxapp:latest",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "ubuntu",
      "Name": "24.04"
    },
    "ImageID": "sha256:733ec474fad62867edb24ec1b0fcdf1c5d6db8c47c2e0b6c9062895936c9fb2f",
    "DiffIDs": [
      "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d",
      "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a",
      "sha256:b47fca8e97e283ef8c51ee325c259ab6b62da33564f66de0476c2b25bcc559c7"
    ],
    "RepoTags": [
      "maheshecrregistry.azurecr.io/maheshnginxapp:latest"
    ],
    "RepoDigests": [
      "maheshecrregistry.azurecr.io/maheshnginxapp@sha256:76ac9b63c8327086aff9c9e619dea0b5a4fbbd55039e673b8f1d719aad307914"
    ],
    "ImageConfig": {
      "architecture": "amd64",
      "author": "Mahesh",
      "created": "2025-02-15T03:09:57.133268324Z",
      "docker_version": "26.1.3",
      "history": [
        {
          "created": "2025-01-27T04:14:00Z",
          "created_by": "/bin/sh -c #(nop)  ARG RELEASE",
          "empty_layer": true
        },
        {
          "created": "2025-01-27T04:14:00Z",
          "created_by": "/bin/sh -c #(nop)  ARG LAUNCHPAD_BUILD_ARCH",
          "empty_layer": true
        },
        {
          "created": "2025-01-27T04:14:00Z",
          "created_by": "/bin/sh -c #(nop)  LABEL org.opencontainers.image.ref.name=ubuntu",
          "empty_layer": true
        },
        {
          "created": "2025-01-27T04:14:00Z",
          "created_by": "/bin/sh -c #(nop)  LABEL org.opencontainers.image.version=24.04",
          "empty_layer": true
        },
        {
          "created": "2025-01-27T04:14:03Z",
          "created_by": "/bin/sh -c #(nop) ADD file:6df775300d76441aa33f31b22c1afce8dfe35c8ffbc14ef27c27009235b12a95 in / "
        },
        {
          "created": "2025-01-27T04:14:03Z",
          "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/bash\"]",
          "empty_layer": true
        },
        {
          "created": "2025-02-14T13:30:05Z",
          "created_by": "/bin/sh -c #(nop)  MAINTAINER Mahesh",
          "empty_layer": true
        },
        {
          "created": "2025-02-14T13:30:40Z",
          "created_by": "/bin/sh -c apt update \u0026\u0026 apt install -y nginx"
        },
        {
          "created": "2025-02-14T13:30:43Z",
          "created_by": "/bin/sh -c #(nop) COPY file:d926aff352d07ea91d825b0c61a2d7fbe49eced33e688bc24f0b30d0099409c9 in /var/www/html/ "
        },
        {
          "created": "2025-02-14T13:30:43Z",
          "created_by": "/bin/sh -c #(nop)  EXPOSE 80",
          "empty_layer": true
        },
        {
          "created": "2025-02-14T13:30:44Z",
          "created_by": "/bin/sh -c #(nop)  ENTRYPOINT [\"/bin/sh\" \"-c\" \"service nginx start \u0026\u0026 /bin/bash\"]",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:53Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.build.buildnumber=20250215.1",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:54Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.build.builduri=vstfs:///Build/Build/47",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:54Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.build.definitionname=mahesh_Docker_Applications",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:54Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.build.repository.name=mahesh_Docker_Applications",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:55Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.build.repository.uri=https://akashz0583@dev.azure.com/akashz0583/mahesh_Docker_Applications/_git/mahesh_Docker_Applications",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:55Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.build.sourcebranchname=main",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:55Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.build.sourceversion=3b9b05c0187277b12e03bff7672bf647c96ab6c1",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:56Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.system.teamfoundationcollectionuri=https://dev.azure.com/akashz0583/",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:56Z",
          "created_by": "/bin/sh -c #(nop)  LABEL com.azure.dev.image.system.teamproject=mahesh_Docker_Applications",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:56Z",
          "created_by": "/bin/sh -c #(nop)  LABEL image.base.digest=sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782",
          "empty_layer": true
        },
        {
          "created": "2025-02-15T03:09:57Z",
          "created_by": "/bin/sh -c #(nop)  LABEL image.base.ref.name=ubuntu:latest",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d",
          "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a",
          "sha256:b47fca8e97e283ef8c51ee325c259ab6b62da33564f66de0476c2b25bcc559c7"
        ]
      },
      "config": {
        "Entrypoint": [
          "/bin/sh",
          "-c",
          "service nginx start \u0026\u0026 /bin/bash"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Image": "sha256:07b6bcb907933216d7f8ba884bc4194084ea8be66109a792761200750ef8c1e5",
        "Labels": {
          "com.azure.dev.image.build.buildnumber": "20250215.1",
          "com.azure.dev.image.build.builduri": "vstfs:///Build/Build/47",
          "com.azure.dev.image.build.definitionname": "mahesh_Docker_Applications",
          "com.azure.dev.image.build.repository.name": "mahesh_Docker_Applications",
          "com.azure.dev.image.build.repository.uri": "https://akashz0583@dev.azure.com/akashz0583/mahesh_Docker_Applications/_git/mahesh_Docker_Applications",
          "com.azure.dev.image.build.sourcebranchname": "main",
          "com.azure.dev.image.build.sourceversion": "3b9b05c0187277b12e03bff7672bf647c96ab6c1",
          "com.azure.dev.image.system.teamfoundationcollectionuri": "https://dev.azure.com/akashz0583/",
          "com.azure.dev.image.system.teamproject": "mahesh_Docker_Applications",
          "image.base.digest": "sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782",
          "image.base.ref.name": "ubuntu:latest",
          "org.opencontainers.image.ref.name": "ubuntu",
          "org.opencontainers.image.version": "24.04"
        },
        "ExposedPorts": {
          "80": {}
        }
      }
    }
  },
  "Results": [
    {
      "Target": "maheshecrregistry.azurecr.io/maheshnginxapp:latest (ubuntu 24.04)",
      "Class": "os-pkgs",
      "Type": "ubuntu",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2016-2781",
          "PkgID": "coreutils@9.4-3ubuntu6",
          "PkgName": "coreutils",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/coreutils@9.4-3ubuntu6?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "e132ebd50ad9fa8b"
          },
          "InstalledVersion": "9.4-3ubuntu6",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-2781",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "coreutils: Non-privileged session can escape to the parent session in chroot",
          "Description": "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-20"
          ],
          "VendorSeverity": {
            "azure": 2,
            "cbl-mariner": 2,
            "nvd": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
              "V2Score": 2.1,
              "V3Score": 6.5
            },
            "redhat": {
              "V2Vector": "AV:L/AC:H/Au:N/C:C/I:C/A:C",
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
              "V2Score": 6.2,
              "V3Score": 8.6
            }
          },
          "References": [
            "http://seclists.org/oss-sec/2016/q1/452",
            "http://www.openwall.com/lists/oss-security/2016/02/28/2",
            "http://www.openwall.com/lists/oss-security/2016/02/28/3",
            "https://access.redhat.com/security/cve/CVE-2016-2781",
            "https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E",
            "https://lore.kernel.org/patchwork/patch/793178/",
            "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.28/v2.28-ReleaseNotes",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-2781",
            "https://www.cve.org/CVERecord?id=CVE-2016-2781"
          ],
          "PublishedDate": "2017-02-07T15:59:00.333Z",
          "LastModifiedDate": "2024-11-21T02:48:47.593Z"
        },
        {
          "VulnerabilityID": "CVE-2022-3219",
          "PkgID": "gpgv@2.4.4-2ubuntu17",
          "PkgName": "gpgv",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/gpgv@2.4.4-2ubuntu17?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "2d79c0e2176ef7bd"
          },
          "InstalledVersion": "2.4.4-2ubuntu17",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-3219",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "gnupg: denial of service issue (resource consumption) using compressed packets",
          "Description": "GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-787"
          ],
          "VendorSeverity": {
            "nvd": 1,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 6.2
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-3219",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2127010",
            "https://dev.gnupg.org/D556",
            "https://dev.gnupg.org/T5993",
            "https://marc.info/?l=oss-security\u0026m=165696590211434\u0026w=4",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-3219",
            "https://security.netapp.com/advisory/ntap-20230324-0001/",
            "https://www.cve.org/CVERecord?id=CVE-2022-3219"
          ],
          "PublishedDate": "2023-02-23T20:15:12.393Z",
          "LastModifiedDate": "2024-11-21T07:19:04.727Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26462",
          "PkgID": "krb5-locales@1.20.1-6ubuntu2.4",
          "PkgName": "krb5-locales",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/krb5-locales@1.20.1-6ubuntu2.4?arch=all\u0026distro=ubuntu-24.04",
            "UID": "43c311d1fad01dcc"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26462",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/kdc/ndr.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26462",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md",
            "https://linux.oracle.com/cve/CVE-2024-26462.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26462",
            "https://security.netapp.com/advisory/ntap-20240415-0012/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26462"
          ],
          "PublishedDate": "2024-02-29T01:44:18.857Z",
          "LastModifiedDate": "2025-02-14T17:29:03.303Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26458",
          "PkgID": "krb5-locales@1.20.1-6ubuntu2.4",
          "PkgName": "krb5-locales",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/krb5-locales@1.20.1-6ubuntu2.4?arch=all\u0026distro=ubuntu-24.04",
            "UID": "43c311d1fad01dcc"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26458",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26458",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md",
            "https://linux.oracle.com/cve/CVE-2024-26458.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26458",
            "https://security.netapp.com/advisory/ntap-20240415-0010/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26458"
          ],
          "PublishedDate": "2024-02-29T01:44:18.78Z",
          "LastModifiedDate": "2024-12-06T21:15:06.28Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26461",
          "PkgID": "krb5-locales@1.20.1-6ubuntu2.4",
          "PkgName": "krb5-locales",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/krb5-locales@1.20.1-6ubuntu2.4?arch=all\u0026distro=ubuntu-24.04",
            "UID": "43c311d1fad01dcc"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26461",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26461",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md",
            "https://linux.oracle.com/cve/CVE-2024-26461.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26461",
            "https://security.netapp.com/advisory/ntap-20240415-0011/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26461"
          ],
          "PublishedDate": "2024-02-29T01:44:18.82Z",
          "LastModifiedDate": "2024-11-21T09:02:26.477Z"
        },
        {
          "VulnerabilityID": "CVE-2025-0395",
          "PkgID": "libc-bin@2.39-0ubuntu8.3",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libc-bin@2.39-0ubuntu8.3?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "d87089a9f0f49ada"
          },
          "InstalledVersion": "2.39-0ubuntu8.3",
          "FixedVersion": "2.39-0ubuntu8.4",
          "Status": "fixed",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2025-0395",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "glibc: buffer overflow in the GNU C Library's assert()",
          "Description": "When the assert() function in the GNU C Library versions 2.13 to 2.40 fails, it does not allocate enough space for the assertion failure message string and size information, which may lead to a buffer overflow if the message string size aligns to page size.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-131"
          ],
          "VendorSeverity": {
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2025/01/22/4",
            "http://www.openwall.com/lists/oss-security/2025/01/23/2",
            "https://access.redhat.com/security/cve/CVE-2025-0395",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-0395",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=32582",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2025-0001",
            "https://sourceware.org/pipermail/libc-announce/2025/000044.html",
            "https://ubuntu.com/security/notices/USN-7259-1",
            "https://ubuntu.com/security/notices/USN-7259-2",
            "https://ubuntu.com/security/notices/USN-7259-3",
            "https://www.cve.org/CVERecord?id=CVE-2025-0395",
            "https://www.openwall.com/lists/oss-security/2025/01/22/4"
          ],
          "PublishedDate": "2025-01-22T13:15:20.933Z",
          "LastModifiedDate": "2025-02-04T20:15:49.587Z"
        },
        {
          "VulnerabilityID": "CVE-2016-20013",
          "PkgID": "libc-bin@2.39-0ubuntu8.3",
          "PkgName": "libc-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libc-bin@2.39-0ubuntu8.3?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "d87089a9f0f49ada"
          },
          "InstalledVersion": "2.39-0ubuntu8.3",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-20013",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Description": "sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "https://akkadia.org/drepper/SHA-crypt.txt",
            "https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/",
            "https://twitter.com/solardiz/status/795601240151457793",
            "https://www.cve.org/CVERecord?id=CVE-2016-20013"
          ],
          "PublishedDate": "2022-02-19T05:15:09.413Z",
          "LastModifiedDate": "2024-11-21T02:47:33.427Z"
        },
        {
          "VulnerabilityID": "CVE-2025-0395",
          "PkgID": "libc6@2.39-0ubuntu8.3",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.3?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "6d9feb7927145822"
          },
          "InstalledVersion": "2.39-0ubuntu8.3",
          "FixedVersion": "2.39-0ubuntu8.4",
          "Status": "fixed",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2025-0395",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "glibc: buffer overflow in the GNU C Library's assert()",
          "Description": "When the assert() function in the GNU C Library versions 2.13 to 2.40 fails, it does not allocate enough space for the assertion failure message string and size information, which may lead to a buffer overflow if the message string size aligns to page size.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-131"
          ],
          "VendorSeverity": {
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2025/01/22/4",
            "http://www.openwall.com/lists/oss-security/2025/01/23/2",
            "https://access.redhat.com/security/cve/CVE-2025-0395",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-0395",
            "https://sourceware.org/bugzilla/show_bug.cgi?id=32582",
            "https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2025-0001",
            "https://sourceware.org/pipermail/libc-announce/2025/000044.html",
            "https://ubuntu.com/security/notices/USN-7259-1",
            "https://ubuntu.com/security/notices/USN-7259-2",
            "https://ubuntu.com/security/notices/USN-7259-3",
            "https://www.cve.org/CVERecord?id=CVE-2025-0395",
            "https://www.openwall.com/lists/oss-security/2025/01/22/4"
          ],
          "PublishedDate": "2025-01-22T13:15:20.933Z",
          "LastModifiedDate": "2025-02-04T20:15:49.587Z"
        },
        {
          "VulnerabilityID": "CVE-2016-20013",
          "PkgID": "libc6@2.39-0ubuntu8.3",
          "PkgName": "libc6",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.3?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "6d9feb7927145822"
          },
          "InstalledVersion": "2.39-0ubuntu8.3",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-20013",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Description": "sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "nvd": 3,
            "ubuntu": 1
          },
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "https://akkadia.org/drepper/SHA-crypt.txt",
            "https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/",
            "https://twitter.com/solardiz/status/795601240151457793",
            "https://www.cve.org/CVERecord?id=CVE-2016-20013"
          ],
          "PublishedDate": "2022-02-19T05:15:09.413Z",
          "LastModifiedDate": "2024-11-21T02:47:33.427Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2236",
          "PkgID": "libgcrypt20@1.10.3-2build1",
          "PkgName": "libgcrypt20",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libgcrypt20@1.10.3-2build1?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "e877dc3e01f1189d"
          },
          "InstalledVersion": "1.10.3-2build1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-2236",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "libgcrypt: vulnerable to Marvin Attack",
          "Description": "A timing-based side-channel flaw was found in libgcrypt's RSA implementation. This issue may allow a remote attacker to initiate a Bleichenbacher-style attack, which can lead to the decryption of RSA ciphertexts.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-208"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9404",
            "https://access.redhat.com/security/cve/CVE-2024-2236",
            "https://bugzilla.redhat.com/2245218",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2245218",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2268268",
            "https://dev.gnupg.org/T7136",
            "https://errata.almalinux.org/9/ALSA-2024-9404.html",
            "https://github.com/tomato42/marvin-toolkit/tree/master/example/libgcrypt",
            "https://gitlab.com/redhat-crypto/libgcrypt/libgcrypt-mirror/-/merge_requests/17",
            "https://linux.oracle.com/cve/CVE-2024-2236.html",
            "https://linux.oracle.com/errata/ELSA-2024-9404.html",
            "https://lists.gnupg.org/pipermail/gcrypt-devel/2024-March/005607.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2236",
            "https://www.cve.org/CVERecord?id=CVE-2024-2236"
          ],
          "PublishedDate": "2024-03-06T22:15:57.977Z",
          "LastModifiedDate": "2024-11-21T09:09:19.41Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26462",
          "PkgID": "libgssapi-krb5-2@1.20.1-6ubuntu2.4",
          "PkgName": "libgssapi-krb5-2",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libgssapi-krb5-2@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "ba55fd2b493d2b02"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26462",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/kdc/ndr.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26462",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md",
            "https://linux.oracle.com/cve/CVE-2024-26462.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26462",
            "https://security.netapp.com/advisory/ntap-20240415-0012/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26462"
          ],
          "PublishedDate": "2024-02-29T01:44:18.857Z",
          "LastModifiedDate": "2025-02-14T17:29:03.303Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26458",
          "PkgID": "libgssapi-krb5-2@1.20.1-6ubuntu2.4",
          "PkgName": "libgssapi-krb5-2",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libgssapi-krb5-2@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "ba55fd2b493d2b02"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26458",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26458",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md",
            "https://linux.oracle.com/cve/CVE-2024-26458.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26458",
            "https://security.netapp.com/advisory/ntap-20240415-0010/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26458"
          ],
          "PublishedDate": "2024-02-29T01:44:18.78Z",
          "LastModifiedDate": "2024-12-06T21:15:06.28Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26461",
          "PkgID": "libgssapi-krb5-2@1.20.1-6ubuntu2.4",
          "PkgName": "libgssapi-krb5-2",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libgssapi-krb5-2@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "ba55fd2b493d2b02"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26461",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26461",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md",
            "https://linux.oracle.com/cve/CVE-2024-26461.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26461",
            "https://security.netapp.com/advisory/ntap-20240415-0011/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26461"
          ],
          "PublishedDate": "2024-02-29T01:44:18.82Z",
          "LastModifiedDate": "2024-11-21T09:02:26.477Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26462",
          "PkgID": "libk5crypto3@1.20.1-6ubuntu2.4",
          "PkgName": "libk5crypto3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libk5crypto3@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "f1ebd8db4df13c2e"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26462",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/kdc/ndr.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26462",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md",
            "https://linux.oracle.com/cve/CVE-2024-26462.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26462",
            "https://security.netapp.com/advisory/ntap-20240415-0012/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26462"
          ],
          "PublishedDate": "2024-02-29T01:44:18.857Z",
          "LastModifiedDate": "2025-02-14T17:29:03.303Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26458",
          "PkgID": "libk5crypto3@1.20.1-6ubuntu2.4",
          "PkgName": "libk5crypto3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libk5crypto3@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "f1ebd8db4df13c2e"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26458",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26458",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md",
            "https://linux.oracle.com/cve/CVE-2024-26458.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26458",
            "https://security.netapp.com/advisory/ntap-20240415-0010/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26458"
          ],
          "PublishedDate": "2024-02-29T01:44:18.78Z",
          "LastModifiedDate": "2024-12-06T21:15:06.28Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26461",
          "PkgID": "libk5crypto3@1.20.1-6ubuntu2.4",
          "PkgName": "libk5crypto3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libk5crypto3@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "f1ebd8db4df13c2e"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26461",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26461",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md",
            "https://linux.oracle.com/cve/CVE-2024-26461.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26461",
            "https://security.netapp.com/advisory/ntap-20240415-0011/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26461"
          ],
          "PublishedDate": "2024-02-29T01:44:18.82Z",
          "LastModifiedDate": "2024-11-21T09:02:26.477Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26462",
          "PkgID": "libkrb5-3@1.20.1-6ubuntu2.4",
          "PkgName": "libkrb5-3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libkrb5-3@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "fec465ff0a6dedcc"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26462",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/kdc/ndr.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26462",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md",
            "https://linux.oracle.com/cve/CVE-2024-26462.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26462",
            "https://security.netapp.com/advisory/ntap-20240415-0012/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26462"
          ],
          "PublishedDate": "2024-02-29T01:44:18.857Z",
          "LastModifiedDate": "2025-02-14T17:29:03.303Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26458",
          "PkgID": "libkrb5-3@1.20.1-6ubuntu2.4",
          "PkgName": "libkrb5-3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libkrb5-3@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "fec465ff0a6dedcc"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26458",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26458",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md",
            "https://linux.oracle.com/cve/CVE-2024-26458.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26458",
            "https://security.netapp.com/advisory/ntap-20240415-0010/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26458"
          ],
          "PublishedDate": "2024-02-29T01:44:18.78Z",
          "LastModifiedDate": "2024-12-06T21:15:06.28Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26461",
          "PkgID": "libkrb5-3@1.20.1-6ubuntu2.4",
          "PkgName": "libkrb5-3",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libkrb5-3@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "fec465ff0a6dedcc"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26461",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26461",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md",
            "https://linux.oracle.com/cve/CVE-2024-26461.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26461",
            "https://security.netapp.com/advisory/ntap-20240415-0011/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26461"
          ],
          "PublishedDate": "2024-02-29T01:44:18.82Z",
          "LastModifiedDate": "2024-11-21T09:02:26.477Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26462",
          "PkgID": "libkrb5support0@1.20.1-6ubuntu2.4",
          "PkgName": "libkrb5support0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libkrb5support0@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "d9b372cd7a8ee7e4"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26462",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/kdc/ndr.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-401"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "nvd": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 2,
            "ubuntu": 2
          },
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26462",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md",
            "https://linux.oracle.com/cve/CVE-2024-26462.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26462",
            "https://security.netapp.com/advisory/ntap-20240415-0012/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26462"
          ],
          "PublishedDate": "2024-02-29T01:44:18.857Z",
          "LastModifiedDate": "2025-02-14T17:29:03.303Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26458",
          "PkgID": "libkrb5support0@1.20.1-6ubuntu2.4",
          "PkgName": "libkrb5support0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libkrb5support0@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "d9b372cd7a8ee7e4"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26458",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.",
          "Severity": "LOW",
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 2,
            "cbl-mariner": 2,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26458",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md",
            "https://linux.oracle.com/cve/CVE-2024-26458.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26458",
            "https://security.netapp.com/advisory/ntap-20240415-0010/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26458"
          ],
          "PublishedDate": "2024-02-29T01:44:18.78Z",
          "LastModifiedDate": "2024-12-06T21:15:06.28Z"
        },
        {
          "VulnerabilityID": "CVE-2024-26461",
          "PkgID": "libkrb5support0@1.20.1-6ubuntu2.4",
          "PkgName": "libkrb5support0",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libkrb5support0@1.20.1-6ubuntu2.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "d9b372cd7a8ee7e4"
          },
          "InstalledVersion": "1.20.1-6ubuntu2.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:d21b9f3b090fa6ae75fb8500fab5fa3828d07219fbdb068ee909adf701126f2a"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-26461",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c",
          "Description": "Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-770"
          ],
          "VendorSeverity": {
            "alma": 2,
            "amazon": 2,
            "azure": 3,
            "cbl-mariner": 3,
            "oracle-oval": 2,
            "photon": 2,
            "redhat": 1,
            "rocky": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:9331",
            "https://access.redhat.com/security/cve/CVE-2024-26461",
            "https://bugzilla.redhat.com/2266731",
            "https://bugzilla.redhat.com/2266740",
            "https://bugzilla.redhat.com/2266742",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266731",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2266740",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461",
            "https://errata.almalinux.org/9/ALSA-2024-9331.html",
            "https://errata.rockylinux.org/RLSA-2024:3268",
            "https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md",
            "https://linux.oracle.com/cve/CVE-2024-26461.html",
            "https://linux.oracle.com/errata/ELSA-2024-9331.html",
            "https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26461",
            "https://security.netapp.com/advisory/ntap-20240415-0011/",
            "https://www.cve.org/CVERecord?id=CVE-2024-26461"
          ],
          "PublishedDate": "2024-02-29T01:44:18.82Z",
          "LastModifiedDate": "2024-11-21T09:02:26.477Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10041",
          "PkgID": "libpam-modules@1.5.3-5ubuntu5.1",
          "PkgName": "libpam-modules",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam-modules@1.5.3-5ubuntu5.1?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "cf565ee8b1a8bfcc"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10041",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: libpam: Libpam vulnerable to read hashed password",
          "Description": "A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-922"
          ],
          "VendorSeverity": {
            "alma": 2,
            "azure": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:11250",
            "https://access.redhat.com/errata/RHSA-2024:9941",
            "https://access.redhat.com/security/cve/CVE-2024-10041",
            "https://bugzilla.redhat.com/2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-11250.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10041.html",
            "https://linux.oracle.com/errata/ELSA-2024-11250.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10041",
            "https://www.cve.org/CVERecord?id=CVE-2024-10041"
          ],
          "PublishedDate": "2024-10-23T14:15:03.97Z",
          "LastModifiedDate": "2024-12-18T10:15:05.85Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10963",
          "PkgID": "libpam-modules@1.5.3-5ubuntu5.1",
          "PkgName": "libpam-modules",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam-modules@1.5.3-5ubuntu5.1?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "cf565ee8b1a8bfcc"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10963",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass",
          "Description": "A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-287"
          ],
          "VendorSeverity": {
            "alma": 3,
            "azure": 3,
            "oracle-oval": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 7.4
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10232",
            "https://access.redhat.com/errata/RHSA-2024:10244",
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:10518",
            "https://access.redhat.com/errata/RHSA-2024:10528",
            "https://access.redhat.com/errata/RHSA-2024:10852",
            "https://access.redhat.com/security/cve/CVE-2024-10963",
            "https://bugzilla.redhat.com/2324291",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-10244.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10963.html",
            "https://linux.oracle.com/errata/ELSA-2024-10379.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10963",
            "https://www.cve.org/CVERecord?id=CVE-2024-10963"
          ],
          "PublishedDate": "2024-11-07T16:15:17.15Z",
          "LastModifiedDate": "2025-02-06T06:15:29.24Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10041",
          "PkgID": "libpam-modules-bin@1.5.3-5ubuntu5.1",
          "PkgName": "libpam-modules-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam-modules-bin@1.5.3-5ubuntu5.1?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "decd456876cb924b"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10041",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: libpam: Libpam vulnerable to read hashed password",
          "Description": "A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-922"
          ],
          "VendorSeverity": {
            "alma": 2,
            "azure": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:11250",
            "https://access.redhat.com/errata/RHSA-2024:9941",
            "https://access.redhat.com/security/cve/CVE-2024-10041",
            "https://bugzilla.redhat.com/2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-11250.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10041.html",
            "https://linux.oracle.com/errata/ELSA-2024-11250.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10041",
            "https://www.cve.org/CVERecord?id=CVE-2024-10041"
          ],
          "PublishedDate": "2024-10-23T14:15:03.97Z",
          "LastModifiedDate": "2024-12-18T10:15:05.85Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10963",
          "PkgID": "libpam-modules-bin@1.5.3-5ubuntu5.1",
          "PkgName": "libpam-modules-bin",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam-modules-bin@1.5.3-5ubuntu5.1?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "decd456876cb924b"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10963",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass",
          "Description": "A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-287"
          ],
          "VendorSeverity": {
            "alma": 3,
            "azure": 3,
            "oracle-oval": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 7.4
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10232",
            "https://access.redhat.com/errata/RHSA-2024:10244",
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:10518",
            "https://access.redhat.com/errata/RHSA-2024:10528",
            "https://access.redhat.com/errata/RHSA-2024:10852",
            "https://access.redhat.com/security/cve/CVE-2024-10963",
            "https://bugzilla.redhat.com/2324291",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-10244.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10963.html",
            "https://linux.oracle.com/errata/ELSA-2024-10379.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10963",
            "https://www.cve.org/CVERecord?id=CVE-2024-10963"
          ],
          "PublishedDate": "2024-11-07T16:15:17.15Z",
          "LastModifiedDate": "2025-02-06T06:15:29.24Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10041",
          "PkgID": "libpam-runtime@1.5.3-5ubuntu5.1",
          "PkgName": "libpam-runtime",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam-runtime@1.5.3-5ubuntu5.1?arch=all\u0026distro=ubuntu-24.04",
            "UID": "91e10e825cb21409"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10041",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: libpam: Libpam vulnerable to read hashed password",
          "Description": "A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-922"
          ],
          "VendorSeverity": {
            "alma": 2,
            "azure": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:11250",
            "https://access.redhat.com/errata/RHSA-2024:9941",
            "https://access.redhat.com/security/cve/CVE-2024-10041",
            "https://bugzilla.redhat.com/2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-11250.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10041.html",
            "https://linux.oracle.com/errata/ELSA-2024-11250.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10041",
            "https://www.cve.org/CVERecord?id=CVE-2024-10041"
          ],
          "PublishedDate": "2024-10-23T14:15:03.97Z",
          "LastModifiedDate": "2024-12-18T10:15:05.85Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10963",
          "PkgID": "libpam-runtime@1.5.3-5ubuntu5.1",
          "PkgName": "libpam-runtime",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam-runtime@1.5.3-5ubuntu5.1?arch=all\u0026distro=ubuntu-24.04",
            "UID": "91e10e825cb21409"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10963",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass",
          "Description": "A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-287"
          ],
          "VendorSeverity": {
            "alma": 3,
            "azure": 3,
            "oracle-oval": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 7.4
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10232",
            "https://access.redhat.com/errata/RHSA-2024:10244",
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:10518",
            "https://access.redhat.com/errata/RHSA-2024:10528",
            "https://access.redhat.com/errata/RHSA-2024:10852",
            "https://access.redhat.com/security/cve/CVE-2024-10963",
            "https://bugzilla.redhat.com/2324291",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-10244.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10963.html",
            "https://linux.oracle.com/errata/ELSA-2024-10379.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10963",
            "https://www.cve.org/CVERecord?id=CVE-2024-10963"
          ],
          "PublishedDate": "2024-11-07T16:15:17.15Z",
          "LastModifiedDate": "2025-02-06T06:15:29.24Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10041",
          "PkgID": "libpam0g@1.5.3-5ubuntu5.1",
          "PkgName": "libpam0g",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam0g@1.5.3-5ubuntu5.1?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "5745156d1a90ccea"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10041",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: libpam: Libpam vulnerable to read hashed password",
          "Description": "A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-922"
          ],
          "VendorSeverity": {
            "alma": 2,
            "azure": 2,
            "oracle-oval": 2,
            "redhat": 2,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 4.7
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:11250",
            "https://access.redhat.com/errata/RHSA-2024:9941",
            "https://access.redhat.com/security/cve/CVE-2024-10041",
            "https://bugzilla.redhat.com/2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-11250.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10041.html",
            "https://linux.oracle.com/errata/ELSA-2024-11250.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10041",
            "https://www.cve.org/CVERecord?id=CVE-2024-10041"
          ],
          "PublishedDate": "2024-10-23T14:15:03.97Z",
          "LastModifiedDate": "2024-12-18T10:15:05.85Z"
        },
        {
          "VulnerabilityID": "CVE-2024-10963",
          "PkgID": "libpam0g@1.5.3-5ubuntu5.1",
          "PkgName": "libpam0g",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libpam0g@1.5.3-5ubuntu5.1?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "5745156d1a90ccea"
          },
          "InstalledVersion": "1.5.3-5ubuntu5.1",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-10963",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass",
          "Description": "A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-287"
          ],
          "VendorSeverity": {
            "alma": 3,
            "azure": 3,
            "oracle-oval": 3,
            "redhat": 3,
            "rocky": 3,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 7.4
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2024:10232",
            "https://access.redhat.com/errata/RHSA-2024:10244",
            "https://access.redhat.com/errata/RHSA-2024:10379",
            "https://access.redhat.com/errata/RHSA-2024:10518",
            "https://access.redhat.com/errata/RHSA-2024:10528",
            "https://access.redhat.com/errata/RHSA-2024:10852",
            "https://access.redhat.com/security/cve/CVE-2024-10963",
            "https://bugzilla.redhat.com/2324291",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2319212",
            "https://bugzilla.redhat.com/show_bug.cgi?id=2324291",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963",
            "https://errata.almalinux.org/9/ALSA-2024-10244.html",
            "https://errata.rockylinux.org/RLSA-2024:10379",
            "https://linux.oracle.com/cve/CVE-2024-10963.html",
            "https://linux.oracle.com/errata/ELSA-2024-10379.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10963",
            "https://www.cve.org/CVERecord?id=CVE-2024-10963"
          ],
          "PublishedDate": "2024-11-07T16:15:17.15Z",
          "LastModifiedDate": "2025-02-06T06:15:29.24Z"
        },
        {
          "VulnerabilityID": "CVE-2024-41996",
          "PkgID": "libssl3t64@3.0.13-0ubuntu3.4",
          "PkgName": "libssl3t64",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.4?arch=amd64\u0026distro=ubuntu-24.04",
            "UID": "39b009225c8dbe18"
          },
          "InstalledVersion": "3.0.13-0ubuntu3.4",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-41996",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "openssl: remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations",
          "Description": "Validating the order of the public keys in the Diffie-Hellman Key Agreement Protocol, when an approved safe prime is used, allows remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations. The client may cause asymmetric resource consumption. The basic attack scenario is that the client must claim that it can only communicate with DHE, and the server must be configured to allow DHE and validate the order of the public key.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-295"
          ],
          "VendorSeverity": {
            "amazon": 2,
            "redhat": 1,
            "ubuntu": 1
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-41996",
            "https://dheatattack.gitlab.io/details/",
            "https://dheatattack.gitlab.io/faq/",
            "https://gist.github.com/c0r0n3r/abccc14d4d96c0442f3a77fa5ca255d1",
            "https://github.com/openssl/openssl/issues/17374",
            "https://github.com/openssl/openssl/pull/25088",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-41996",
            "https://openssl-library.org/post/2022-10-21-tls-groups-configuration/",
            "https://www.cve.org/CVERecord?id=CVE-2024-41996"
          ],
          "PublishedDate": "2024-08-26T06:15:04.603Z",
          "LastModifiedDate": "2024-08-26T16:35:11.247Z"
        },
        {
          "VulnerabilityID": "CVE-2024-56433",
          "PkgID": "login@1:4.13+dfsg1-4ubuntu3.2",
          "PkgName": "login",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/login@4.13%2Bdfsg1-4ubuntu3.2?arch=amd64\u0026distro=ubuntu-24.04\u0026epoch=1",
            "UID": "e4c161856466d4dd"
          },
          "InstalledVersion": "1:4.13+dfsg1-4ubuntu3.2",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-56433",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "shadow-utils: Default subordinate ID configuration in /etc/login.defs could lead to compromise",
          "Description": "shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-1188"
          ],
          "VendorSeverity": {
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 3.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-56433",
            "https://github.com/shadow-maint/shadow/blob/e2512d5741d4a44bdd81a8c2d0029b6222728cf0/etc/login.defs#L238-L241",
            "https://github.com/shadow-maint/shadow/issues/1157",
            "https://github.com/shadow-maint/shadow/releases/tag/4.4",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-56433",
            "https://www.cve.org/CVERecord?id=CVE-2024-56433"
          ],
          "PublishedDate": "2024-12-26T09:15:07.267Z",
          "LastModifiedDate": "2024-12-26T09:15:07.267Z"
        },
        {
          "VulnerabilityID": "CVE-2024-56433",
          "PkgID": "passwd@1:4.13+dfsg1-4ubuntu3.2",
          "PkgName": "passwd",
          "PkgIdentifier": {
            "PURL": "pkg:deb/ubuntu/passwd@4.13%2Bdfsg1-4ubuntu3.2?arch=amd64\u0026distro=ubuntu-24.04\u0026epoch=1",
            "UID": "933f5fd5d23d7886"
          },
          "InstalledVersion": "1:4.13+dfsg1-4ubuntu3.2",
          "Status": "affected",
          "Layer": {
            "DiffID": "sha256:4b7c01ed0534d4f9be9cf97d068da1598c6c20b26cb6134fad066defdb6d541d"
          },
          "SeveritySource": "ubuntu",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-56433",
          "DataSource": {
            "ID": "ubuntu",
            "Name": "Ubuntu CVE Tracker",
            "URL": "https://git.launchpad.net/ubuntu-cve-tracker"
          },
          "Title": "shadow-utils: Default subordinate ID configuration in /etc/login.defs could lead to compromise",
          "Description": "shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-1188"
          ],
          "VendorSeverity": {
            "redhat": 1,
            "ubuntu": 2
          },
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
              "V3Score": 3.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2024-56433",
            "https://github.com/shadow-maint/shadow/blob/e2512d5741d4a44bdd81a8c2d0029b6222728cf0/etc/login.defs#L238-L241",
            "https://github.com/shadow-maint/shadow/issues/1157",
            "https://github.com/shadow-maint/shadow/releases/tag/4.4",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-56433",
            "https://www.cve.org/CVERecord?id=CVE-2024-56433"
          ],
          "PublishedDate": "2024-12-26T09:15:07.267Z",
          "LastModifiedDate": "2024-12-26T09:15:07.267Z"
        }
      ]
    }
  ]
}
