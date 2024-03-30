
# CS 564 Capstone Project
- Team Cryptid

# Setup vulnerable windows VM
- Install Windows 10 VM
- Disable Windows firewall
- Set the following registry values at HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint:
    - RestrictDriverInstallationToAdministrators    REG_DWORD    0x0
    - NoWarningNoElevationOnInstall                 REG_DWORD    0x1
- Donwload and install JDK 11 from https://aka.ms/download-jdk/microsoft-jdk-11.0.22-windows-x64.msi
    - Make sure to enable the option to add JAVA_HOME to the PATH
    - You can run `java --version` in the Windows Command prompt to see if it installed properly
- Download vulnerable Jenkins version from https://get.jenkins.io/war/1.625/
- To run Jenkins, execute `java -jar /path/to/jenkins.war`
- Now Jenkins should be running on port 8080

# Running the Exploit
- Run `python exploit.py <IP> <PORT> <PATH>` where IP and PORT represent the target Jenkins server and PATH is a local path to a groovy file to execute on the target
    - Remember to change the IP and filename in the Groovy code

## Info
- Target            : Windows 10
- Initial Compromise: Jenkins Script Console RCE
- Priv Esc          : Printer Nightmare (CVE-2021-34527)
- Purpose           : Obtain local/domain credentials + other sensitive files

## Obfuscation
- LLVM-based (https://github.com/cainiao1992/ollvm-mingw)
- Loader + decryptor
- Lots of ideas here: https://book.hacktricks.xyz/windows-hardening/av-bypass
 
