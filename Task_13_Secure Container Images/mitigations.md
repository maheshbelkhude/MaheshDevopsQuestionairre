<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style>
      * {
        font-family: Arial, Helvetica, sans-serif;
      }
      h1 {
        text-align: center;
      }
      .group-header th {
        font-size: 200%;
      }
      .sub-header th {
        font-size: 150%;
      }
      table, th, td {
        border: 1px solid black;
        border-collapse: collapse;
        white-space: nowrap;
        padding: .3em;
      }
      table {
        margin: 0 auto;
      }
      .severity {
        text-align: center;
        font-weight: bold;
        color: #fafafa;
      }
      .severity-LOW .severity { background-color: #5fbb31; }
      .severity-MEDIUM .severity { background-color: #e9c600; }
      .severity-HIGH .severity { background-color: #ff8800; }
      .severity-CRITICAL .severity { background-color: #e40000; }
      .severity-UNKNOWN .severity { background-color: #747474; }
      .severity-LOW { background-color: #5fbb3160; }
      .severity-MEDIUM { background-color: #e9c60060; }
      .severity-HIGH { background-color: #ff880060; }
      .severity-CRITICAL { background-color: #e4000060; }
      .severity-UNKNOWN { background-color: #74747460; }
      table tr td:first-of-type {
        font-weight: bold;
      }
      .links a,
      .links[data-more-links=on] a {
        display: block;
      }
      .links[data-more-links=off] a:nth-of-type(1n+5) {
        display: none;
      }
      a.toggle-more-links { cursor: pointer; }
    </style>
    <title>maheshecrregistry.azurecr.io/maheshnginxapp:latest (ubuntu 24.04) - Trivy Report - 2025-02-15 03:55:22.893009142 +0000 UTC m=+1.773579812 </title>
    <script>
      window.onload = function() {
        document.querySelectorAll('td.links').forEach(function(linkCell) {
          var links = [].concat.apply([], linkCell.querySelectorAll('a'));
          [].sort.apply(links, function(a, b) {
            return a.href > b.href ? 1 : -1;
          });
          links.forEach(function(link, idx) {
            if (links.length > 3 && 3 === idx) {
              var toggleLink = document.createElement('a');
              toggleLink.innerText = "Toggle more links";
              toggleLink.href = "#toggleMore";
              toggleLink.setAttribute("class", "toggle-more-links");
              linkCell.appendChild(toggleLink);
            }
            linkCell.appendChild(link);
          });
        });
        document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
          toggleLink.onclick = function() {
            var expanded = toggleLink.parentElement.getAttribute("data-more-links");
            toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
            return false;
          };
        });
      };
    </script>
  </head>
  <body>
    <h1>maheshecrregistry.azurecr.io/maheshnginxapp:latest (ubuntu 24.04) - Trivy Report - 2025-02-15 03:55:22.893045246 +0000 UTC m=+1.773615913</h1>
    <table>
      <tr class="group-header"><th colspan="6">ubuntu</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">coreutils</td>
        <td>CVE-2016-2781</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">9.4-3ubuntu6</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="http://seclists.org/oss-sec/2016/q1/452">http://seclists.org/oss-sec/2016/q1/452</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/28/2">http://www.openwall.com/lists/oss-security/2016/02/28/2</a>
          <a href="http://www.openwall.com/lists/oss-security/2016/02/28/3">http://www.openwall.com/lists/oss-security/2016/02/28/3</a>
          <a href="https://access.redhat.com/security/cve/CVE-2016-2781">https://access.redhat.com/security/cve/CVE-2016-2781</a>
          <a href="https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E">https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E</a>
          <a href="https://lore.kernel.org/patchwork/patch/793178/">https://lore.kernel.org/patchwork/patch/793178/</a>
          <a href="https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.28/v2.28-ReleaseNotes">https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.28/v2.28-ReleaseNotes</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-2781">https://nvd.nist.gov/vuln/detail/CVE-2016-2781</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2016-2781">https://www.cve.org/CVERecord?id=CVE-2016-2781</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">gpgv</td>
        <td>CVE-2022-3219</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">2.4.4-2ubuntu17</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2022-3219">https://access.redhat.com/security/cve/CVE-2022-3219</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2127010">https://bugzilla.redhat.com/show_bug.cgi?id=2127010</a>
          <a href="https://dev.gnupg.org/D556">https://dev.gnupg.org/D556</a>
          <a href="https://dev.gnupg.org/T5993">https://dev.gnupg.org/T5993</a>
          <a href="https://marc.info/?l=oss-security&amp;m=165696590211434&amp;w=4">https://marc.info/?l=oss-security&amp;m=165696590211434&amp;w=4</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-3219">https://nvd.nist.gov/vuln/detail/CVE-2022-3219</a>
          <a href="https://security.netapp.com/advisory/ntap-20230324-0001/">https://security.netapp.com/advisory/ntap-20230324-0001/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2022-3219">https://www.cve.org/CVERecord?id=CVE-2022-3219</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">krb5-locales</td>
        <td>CVE-2024-26462</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26462">https://access.redhat.com/security/cve/CVE-2024-26462</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26462.html">https://linux.oracle.com/cve/CVE-2024-26462.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26462">https://nvd.nist.gov/vuln/detail/CVE-2024-26462</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0012/">https://security.netapp.com/advisory/ntap-20240415-0012/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26462">https://www.cve.org/CVERecord?id=CVE-2024-26462</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">krb5-locales</td>
        <td>CVE-2024-26458</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26458">https://access.redhat.com/security/cve/CVE-2024-26458</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26458.html">https://linux.oracle.com/cve/CVE-2024-26458.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26458">https://nvd.nist.gov/vuln/detail/CVE-2024-26458</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0010/">https://security.netapp.com/advisory/ntap-20240415-0010/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26458">https://www.cve.org/CVERecord?id=CVE-2024-26458</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">krb5-locales</td>
        <td>CVE-2024-26461</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26461">https://access.redhat.com/security/cve/CVE-2024-26461</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26461.html">https://linux.oracle.com/cve/CVE-2024-26461.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26461">https://nvd.nist.gov/vuln/detail/CVE-2024-26461</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0011/">https://security.netapp.com/advisory/ntap-20240415-0011/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26461">https://www.cve.org/CVERecord?id=CVE-2024-26461</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2025-0395</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.39-0ubuntu8.3</td>
        <td>2.39-0ubuntu8.4</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2025/01/22/4">http://www.openwall.com/lists/oss-security/2025/01/22/4</a>
          <a href="http://www.openwall.com/lists/oss-security/2025/01/23/2">http://www.openwall.com/lists/oss-security/2025/01/23/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2025-0395">https://access.redhat.com/security/cve/CVE-2025-0395</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2025-0395">https://nvd.nist.gov/vuln/detail/CVE-2025-0395</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=32582">https://sourceware.org/bugzilla/show_bug.cgi?id=32582</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2025-0001">https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2025-0001</a>
          <a href="https://sourceware.org/pipermail/libc-announce/2025/000044.html">https://sourceware.org/pipermail/libc-announce/2025/000044.html</a>
          <a href="https://ubuntu.com/security/notices/USN-7259-1">https://ubuntu.com/security/notices/USN-7259-1</a>
          <a href="https://ubuntu.com/security/notices/USN-7259-2">https://ubuntu.com/security/notices/USN-7259-2</a>
          <a href="https://ubuntu.com/security/notices/USN-7259-3">https://ubuntu.com/security/notices/USN-7259-3</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2025-0395">https://www.cve.org/CVERecord?id=CVE-2025-0395</a>
          <a href="https://www.openwall.com/lists/oss-security/2025/01/22/4">https://www.openwall.com/lists/oss-security/2025/01/22/4</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libc-bin</td>
        <td>CVE-2016-20013</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">2.39-0ubuntu8.3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://akkadia.org/drepper/SHA-crypt.txt">https://akkadia.org/drepper/SHA-crypt.txt</a>
          <a href="https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/">https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/</a>
          <a href="https://twitter.com/solardiz/status/795601240151457793">https://twitter.com/solardiz/status/795601240151457793</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2016-20013">https://www.cve.org/CVERecord?id=CVE-2016-20013</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libc6</td>
        <td>CVE-2025-0395</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.39-0ubuntu8.3</td>
        <td>2.39-0ubuntu8.4</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2025/01/22/4">http://www.openwall.com/lists/oss-security/2025/01/22/4</a>
          <a href="http://www.openwall.com/lists/oss-security/2025/01/23/2">http://www.openwall.com/lists/oss-security/2025/01/23/2</a>
          <a href="https://access.redhat.com/security/cve/CVE-2025-0395">https://access.redhat.com/security/cve/CVE-2025-0395</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2025-0395">https://nvd.nist.gov/vuln/detail/CVE-2025-0395</a>
          <a href="https://sourceware.org/bugzilla/show_bug.cgi?id=32582">https://sourceware.org/bugzilla/show_bug.cgi?id=32582</a>
          <a href="https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2025-0001">https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2025-0001</a>
          <a href="https://sourceware.org/pipermail/libc-announce/2025/000044.html">https://sourceware.org/pipermail/libc-announce/2025/000044.html</a>
          <a href="https://ubuntu.com/security/notices/USN-7259-1">https://ubuntu.com/security/notices/USN-7259-1</a>
          <a href="https://ubuntu.com/security/notices/USN-7259-2">https://ubuntu.com/security/notices/USN-7259-2</a>
          <a href="https://ubuntu.com/security/notices/USN-7259-3">https://ubuntu.com/security/notices/USN-7259-3</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2025-0395">https://www.cve.org/CVERecord?id=CVE-2025-0395</a>
          <a href="https://www.openwall.com/lists/oss-security/2025/01/22/4">https://www.openwall.com/lists/oss-security/2025/01/22/4</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libc6</td>
        <td>CVE-2016-20013</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">2.39-0ubuntu8.3</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://akkadia.org/drepper/SHA-crypt.txt">https://akkadia.org/drepper/SHA-crypt.txt</a>
          <a href="https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/">https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/</a>
          <a href="https://twitter.com/solardiz/status/795601240151457793">https://twitter.com/solardiz/status/795601240151457793</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2016-20013">https://www.cve.org/CVERecord?id=CVE-2016-20013</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libgcrypt20</td>
        <td>CVE-2024-2236</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.10.3-2build1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9404">https://access.redhat.com/errata/RHSA-2024:9404</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-2236">https://access.redhat.com/security/cve/CVE-2024-2236</a>
          <a href="https://bugzilla.redhat.com/2245218">https://bugzilla.redhat.com/2245218</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2245218">https://bugzilla.redhat.com/show_bug.cgi?id=2245218</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2268268">https://bugzilla.redhat.com/show_bug.cgi?id=2268268</a>
          <a href="https://dev.gnupg.org/T7136">https://dev.gnupg.org/T7136</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9404.html">https://errata.almalinux.org/9/ALSA-2024-9404.html</a>
          <a href="https://github.com/tomato42/marvin-toolkit/tree/master/example/libgcrypt">https://github.com/tomato42/marvin-toolkit/tree/master/example/libgcrypt</a>
          <a href="https://gitlab.com/redhat-crypto/libgcrypt/libgcrypt-mirror/-/merge_requests/17">https://gitlab.com/redhat-crypto/libgcrypt/libgcrypt-mirror/-/merge_requests/17</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-2236.html">https://linux.oracle.com/cve/CVE-2024-2236.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9404.html">https://linux.oracle.com/errata/ELSA-2024-9404.html</a>
          <a href="https://lists.gnupg.org/pipermail/gcrypt-devel/2024-March/005607.html">https://lists.gnupg.org/pipermail/gcrypt-devel/2024-March/005607.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-2236">https://nvd.nist.gov/vuln/detail/CVE-2024-2236</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-2236">https://www.cve.org/CVERecord?id=CVE-2024-2236</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2024-26462</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26462">https://access.redhat.com/security/cve/CVE-2024-26462</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26462.html">https://linux.oracle.com/cve/CVE-2024-26462.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26462">https://nvd.nist.gov/vuln/detail/CVE-2024-26462</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0012/">https://security.netapp.com/advisory/ntap-20240415-0012/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26462">https://www.cve.org/CVERecord?id=CVE-2024-26462</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2024-26458</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26458">https://access.redhat.com/security/cve/CVE-2024-26458</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26458.html">https://linux.oracle.com/cve/CVE-2024-26458.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26458">https://nvd.nist.gov/vuln/detail/CVE-2024-26458</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0010/">https://security.netapp.com/advisory/ntap-20240415-0010/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26458">https://www.cve.org/CVERecord?id=CVE-2024-26458</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libgssapi-krb5-2</td>
        <td>CVE-2024-26461</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26461">https://access.redhat.com/security/cve/CVE-2024-26461</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26461.html">https://linux.oracle.com/cve/CVE-2024-26461.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26461">https://nvd.nist.gov/vuln/detail/CVE-2024-26461</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0011/">https://security.netapp.com/advisory/ntap-20240415-0011/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26461">https://www.cve.org/CVERecord?id=CVE-2024-26461</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2024-26462</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26462">https://access.redhat.com/security/cve/CVE-2024-26462</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26462.html">https://linux.oracle.com/cve/CVE-2024-26462.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26462">https://nvd.nist.gov/vuln/detail/CVE-2024-26462</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0012/">https://security.netapp.com/advisory/ntap-20240415-0012/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26462">https://www.cve.org/CVERecord?id=CVE-2024-26462</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2024-26458</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26458">https://access.redhat.com/security/cve/CVE-2024-26458</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26458.html">https://linux.oracle.com/cve/CVE-2024-26458.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26458">https://nvd.nist.gov/vuln/detail/CVE-2024-26458</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0010/">https://security.netapp.com/advisory/ntap-20240415-0010/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26458">https://www.cve.org/CVERecord?id=CVE-2024-26458</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libk5crypto3</td>
        <td>CVE-2024-26461</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26461">https://access.redhat.com/security/cve/CVE-2024-26461</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26461.html">https://linux.oracle.com/cve/CVE-2024-26461.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26461">https://nvd.nist.gov/vuln/detail/CVE-2024-26461</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0011/">https://security.netapp.com/advisory/ntap-20240415-0011/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26461">https://www.cve.org/CVERecord?id=CVE-2024-26461</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2024-26462</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26462">https://access.redhat.com/security/cve/CVE-2024-26462</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26462.html">https://linux.oracle.com/cve/CVE-2024-26462.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26462">https://nvd.nist.gov/vuln/detail/CVE-2024-26462</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0012/">https://security.netapp.com/advisory/ntap-20240415-0012/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26462">https://www.cve.org/CVERecord?id=CVE-2024-26462</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2024-26458</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26458">https://access.redhat.com/security/cve/CVE-2024-26458</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26458.html">https://linux.oracle.com/cve/CVE-2024-26458.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26458">https://nvd.nist.gov/vuln/detail/CVE-2024-26458</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0010/">https://security.netapp.com/advisory/ntap-20240415-0010/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26458">https://www.cve.org/CVERecord?id=CVE-2024-26458</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libkrb5-3</td>
        <td>CVE-2024-26461</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26461">https://access.redhat.com/security/cve/CVE-2024-26461</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26461.html">https://linux.oracle.com/cve/CVE-2024-26461.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26461">https://nvd.nist.gov/vuln/detail/CVE-2024-26461</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0011/">https://security.netapp.com/advisory/ntap-20240415-0011/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26461">https://www.cve.org/CVERecord?id=CVE-2024-26461</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2024-26462</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26462">https://access.redhat.com/security/cve/CVE-2024-26462</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26462.html">https://linux.oracle.com/cve/CVE-2024-26462.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26462">https://nvd.nist.gov/vuln/detail/CVE-2024-26462</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0012/">https://security.netapp.com/advisory/ntap-20240415-0012/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26462">https://www.cve.org/CVERecord?id=CVE-2024-26462</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2024-26458</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26458">https://access.redhat.com/security/cve/CVE-2024-26458</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26458.html">https://linux.oracle.com/cve/CVE-2024-26458.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26458">https://nvd.nist.gov/vuln/detail/CVE-2024-26458</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0010/">https://security.netapp.com/advisory/ntap-20240415-0010/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26458">https://www.cve.org/CVERecord?id=CVE-2024-26458</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libkrb5support0</td>
        <td>CVE-2024-26461</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">1.20.1-6ubuntu2.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:9331">https://access.redhat.com/errata/RHSA-2024:9331</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-26461">https://access.redhat.com/security/cve/CVE-2024-26461</a>
          <a href="https://bugzilla.redhat.com/2266731">https://bugzilla.redhat.com/2266731</a>
          <a href="https://bugzilla.redhat.com/2266740">https://bugzilla.redhat.com/2266740</a>
          <a href="https://bugzilla.redhat.com/2266742">https://bugzilla.redhat.com/2266742</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266731">https://bugzilla.redhat.com/show_bug.cgi?id=2266731</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2266740">https://bugzilla.redhat.com/show_bug.cgi?id=2266740</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-9331.html">https://errata.almalinux.org/9/ALSA-2024-9331.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:3268">https://errata.rockylinux.org/RLSA-2024:3268</a>
          <a href="https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md">https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-26461.html">https://linux.oracle.com/cve/CVE-2024-26461.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-9331.html">https://linux.oracle.com/errata/ELSA-2024-9331.html</a>
          <a href="https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html">https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-26461">https://nvd.nist.gov/vuln/detail/CVE-2024-26461</a>
          <a href="https://security.netapp.com/advisory/ntap-20240415-0011/">https://security.netapp.com/advisory/ntap-20240415-0011/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-26461">https://www.cve.org/CVERecord?id=CVE-2024-26461</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam-modules</td>
        <td>CVE-2024-10041</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:11250">https://access.redhat.com/errata/RHSA-2024:11250</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:9941">https://access.redhat.com/errata/RHSA-2024:9941</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10041">https://access.redhat.com/security/cve/CVE-2024-10041</a>
          <a href="https://bugzilla.redhat.com/2319212">https://bugzilla.redhat.com/2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-11250.html">https://errata.almalinux.org/9/ALSA-2024-11250.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10041.html">https://linux.oracle.com/cve/CVE-2024-10041.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-11250.html">https://linux.oracle.com/errata/ELSA-2024-11250.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10041">https://nvd.nist.gov/vuln/detail/CVE-2024-10041</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10041">https://www.cve.org/CVERecord?id=CVE-2024-10041</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam-modules</td>
        <td>CVE-2024-10963</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10232">https://access.redhat.com/errata/RHSA-2024:10232</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10244">https://access.redhat.com/errata/RHSA-2024:10244</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10518">https://access.redhat.com/errata/RHSA-2024:10518</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10528">https://access.redhat.com/errata/RHSA-2024:10528</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10852">https://access.redhat.com/errata/RHSA-2024:10852</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10963">https://access.redhat.com/security/cve/CVE-2024-10963</a>
          <a href="https://bugzilla.redhat.com/2324291">https://bugzilla.redhat.com/2324291</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-10244.html">https://errata.almalinux.org/9/ALSA-2024-10244.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10963.html">https://linux.oracle.com/cve/CVE-2024-10963.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-10379.html">https://linux.oracle.com/errata/ELSA-2024-10379.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10963">https://nvd.nist.gov/vuln/detail/CVE-2024-10963</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10963">https://www.cve.org/CVERecord?id=CVE-2024-10963</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam-modules-bin</td>
        <td>CVE-2024-10041</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:11250">https://access.redhat.com/errata/RHSA-2024:11250</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:9941">https://access.redhat.com/errata/RHSA-2024:9941</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10041">https://access.redhat.com/security/cve/CVE-2024-10041</a>
          <a href="https://bugzilla.redhat.com/2319212">https://bugzilla.redhat.com/2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-11250.html">https://errata.almalinux.org/9/ALSA-2024-11250.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10041.html">https://linux.oracle.com/cve/CVE-2024-10041.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-11250.html">https://linux.oracle.com/errata/ELSA-2024-11250.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10041">https://nvd.nist.gov/vuln/detail/CVE-2024-10041</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10041">https://www.cve.org/CVERecord?id=CVE-2024-10041</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam-modules-bin</td>
        <td>CVE-2024-10963</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10232">https://access.redhat.com/errata/RHSA-2024:10232</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10244">https://access.redhat.com/errata/RHSA-2024:10244</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10518">https://access.redhat.com/errata/RHSA-2024:10518</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10528">https://access.redhat.com/errata/RHSA-2024:10528</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10852">https://access.redhat.com/errata/RHSA-2024:10852</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10963">https://access.redhat.com/security/cve/CVE-2024-10963</a>
          <a href="https://bugzilla.redhat.com/2324291">https://bugzilla.redhat.com/2324291</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-10244.html">https://errata.almalinux.org/9/ALSA-2024-10244.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10963.html">https://linux.oracle.com/cve/CVE-2024-10963.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-10379.html">https://linux.oracle.com/errata/ELSA-2024-10379.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10963">https://nvd.nist.gov/vuln/detail/CVE-2024-10963</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10963">https://www.cve.org/CVERecord?id=CVE-2024-10963</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam-runtime</td>
        <td>CVE-2024-10041</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:11250">https://access.redhat.com/errata/RHSA-2024:11250</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:9941">https://access.redhat.com/errata/RHSA-2024:9941</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10041">https://access.redhat.com/security/cve/CVE-2024-10041</a>
          <a href="https://bugzilla.redhat.com/2319212">https://bugzilla.redhat.com/2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-11250.html">https://errata.almalinux.org/9/ALSA-2024-11250.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10041.html">https://linux.oracle.com/cve/CVE-2024-10041.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-11250.html">https://linux.oracle.com/errata/ELSA-2024-11250.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10041">https://nvd.nist.gov/vuln/detail/CVE-2024-10041</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10041">https://www.cve.org/CVERecord?id=CVE-2024-10041</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam-runtime</td>
        <td>CVE-2024-10963</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10232">https://access.redhat.com/errata/RHSA-2024:10232</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10244">https://access.redhat.com/errata/RHSA-2024:10244</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10518">https://access.redhat.com/errata/RHSA-2024:10518</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10528">https://access.redhat.com/errata/RHSA-2024:10528</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10852">https://access.redhat.com/errata/RHSA-2024:10852</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10963">https://access.redhat.com/security/cve/CVE-2024-10963</a>
          <a href="https://bugzilla.redhat.com/2324291">https://bugzilla.redhat.com/2324291</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-10244.html">https://errata.almalinux.org/9/ALSA-2024-10244.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10963.html">https://linux.oracle.com/cve/CVE-2024-10963.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-10379.html">https://linux.oracle.com/errata/ELSA-2024-10379.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10963">https://nvd.nist.gov/vuln/detail/CVE-2024-10963</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10963">https://www.cve.org/CVERecord?id=CVE-2024-10963</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam0g</td>
        <td>CVE-2024-10041</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:11250">https://access.redhat.com/errata/RHSA-2024:11250</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:9941">https://access.redhat.com/errata/RHSA-2024:9941</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10041">https://access.redhat.com/security/cve/CVE-2024-10041</a>
          <a href="https://bugzilla.redhat.com/2319212">https://bugzilla.redhat.com/2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-11250.html">https://errata.almalinux.org/9/ALSA-2024-11250.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10041.html">https://linux.oracle.com/cve/CVE-2024-10041.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-11250.html">https://linux.oracle.com/errata/ELSA-2024-11250.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10041">https://nvd.nist.gov/vuln/detail/CVE-2024-10041</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10041">https://www.cve.org/CVERecord?id=CVE-2024-10041</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">libpam0g</td>
        <td>CVE-2024-10963</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1.5.3-5ubuntu5.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/errata/RHSA-2024:10232">https://access.redhat.com/errata/RHSA-2024:10232</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10244">https://access.redhat.com/errata/RHSA-2024:10244</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10379">https://access.redhat.com/errata/RHSA-2024:10379</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10518">https://access.redhat.com/errata/RHSA-2024:10518</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10528">https://access.redhat.com/errata/RHSA-2024:10528</a>
          <a href="https://access.redhat.com/errata/RHSA-2024:10852">https://access.redhat.com/errata/RHSA-2024:10852</a>
          <a href="https://access.redhat.com/security/cve/CVE-2024-10963">https://access.redhat.com/security/cve/CVE-2024-10963</a>
          <a href="https://bugzilla.redhat.com/2324291">https://bugzilla.redhat.com/2324291</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2319212">https://bugzilla.redhat.com/show_bug.cgi?id=2319212</a>
          <a href="https://bugzilla.redhat.com/show_bug.cgi?id=2324291">https://bugzilla.redhat.com/show_bug.cgi?id=2324291</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10041</a>
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-10963</a>
          <a href="https://errata.almalinux.org/9/ALSA-2024-10244.html">https://errata.almalinux.org/9/ALSA-2024-10244.html</a>
          <a href="https://errata.rockylinux.org/RLSA-2024:10379">https://errata.rockylinux.org/RLSA-2024:10379</a>
          <a href="https://linux.oracle.com/cve/CVE-2024-10963.html">https://linux.oracle.com/cve/CVE-2024-10963.html</a>
          <a href="https://linux.oracle.com/errata/ELSA-2024-10379.html">https://linux.oracle.com/errata/ELSA-2024-10379.html</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-10963">https://nvd.nist.gov/vuln/detail/CVE-2024-10963</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-10963">https://www.cve.org/CVERecord?id=CVE-2024-10963</a>
        </td>
      </tr>
      <tr class="severity-LOW">
        <td class="pkg-name">libssl3t64</td>
        <td>CVE-2024-41996</td>
        <td class="severity">LOW</td>
        <td class="pkg-version">3.0.13-0ubuntu3.4</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2024-41996">https://access.redhat.com/security/cve/CVE-2024-41996</a>
          <a href="https://dheatattack.gitlab.io/details/">https://dheatattack.gitlab.io/details/</a>
          <a href="https://dheatattack.gitlab.io/faq/">https://dheatattack.gitlab.io/faq/</a>
          <a href="https://gist.github.com/c0r0n3r/abccc14d4d96c0442f3a77fa5ca255d1">https://gist.github.com/c0r0n3r/abccc14d4d96c0442f3a77fa5ca255d1</a>
          <a href="https://github.com/openssl/openssl/issues/17374">https://github.com/openssl/openssl/issues/17374</a>
          <a href="https://github.com/openssl/openssl/pull/25088">https://github.com/openssl/openssl/pull/25088</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-41996">https://nvd.nist.gov/vuln/detail/CVE-2024-41996</a>
          <a href="https://openssl-library.org/post/2022-10-21-tls-groups-configuration/">https://openssl-library.org/post/2022-10-21-tls-groups-configuration/</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-41996">https://www.cve.org/CVERecord?id=CVE-2024-41996</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">login</td>
        <td>CVE-2024-56433</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1:4.13+dfsg1-4ubuntu3.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2024-56433">https://access.redhat.com/security/cve/CVE-2024-56433</a>
          <a href="https://github.com/shadow-maint/shadow/blob/e2512d5741d4a44bdd81a8c2d0029b6222728cf0/etc/login.defs#L238-L241">https://github.com/shadow-maint/shadow/blob/e2512d5741d4a44bdd81a8c2d0029b6222728cf0/etc/login.defs#L238-L241</a>
          <a href="https://github.com/shadow-maint/shadow/issues/1157">https://github.com/shadow-maint/shadow/issues/1157</a>
          <a href="https://github.com/shadow-maint/shadow/releases/tag/4.4">https://github.com/shadow-maint/shadow/releases/tag/4.4</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-56433">https://nvd.nist.gov/vuln/detail/CVE-2024-56433</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-56433">https://www.cve.org/CVERecord?id=CVE-2024-56433</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">passwd</td>
        <td>CVE-2024-56433</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">1:4.13+dfsg1-4ubuntu3.2</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://access.redhat.com/security/cve/CVE-2024-56433">https://access.redhat.com/security/cve/CVE-2024-56433</a>
          <a href="https://github.com/shadow-maint/shadow/blob/e2512d5741d4a44bdd81a8c2d0029b6222728cf0/etc/login.defs#L238-L241">https://github.com/shadow-maint/shadow/blob/e2512d5741d4a44bdd81a8c2d0029b6222728cf0/etc/login.defs#L238-L241</a>
          <a href="https://github.com/shadow-maint/shadow/issues/1157">https://github.com/shadow-maint/shadow/issues/1157</a>
          <a href="https://github.com/shadow-maint/shadow/releases/tag/4.4">https://github.com/shadow-maint/shadow/releases/tag/4.4</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2024-56433">https://nvd.nist.gov/vuln/detail/CVE-2024-56433</a>
          <a href="https://www.cve.org/CVERecord?id=CVE-2024-56433">https://www.cve.org/CVERecord?id=CVE-2024-56433</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
