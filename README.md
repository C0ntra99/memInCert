# **MemInCert**
All credit goes to Shane Rudy. He was the one who did a write up on this process, I just automated it with a script. Be sure the check out his write up!
https://www.coalfire.com/The-Coalfire-Blog/May-2018/PowerShell-In-Memory-Injection-Using-CertUtil-exe

### What memInCert does
Shane does a much better job explaining it so go read his. 
MemInCert will generate a metasploit payload and then use Invoke-CradleCrafter to obfuscate that payload to avoid detection by windows defender. That obfuscated payload will then be turned into a certificate file, Shane uses certutil.exe on a different windows computer but from my testing either way works. The one liner that gets generated in command.txt will deliver the certificate and use certutil.exe to decode the "certificate" and run the meterpreter stager.

# Usage

### Requirements

 - metasploit
 - msfvenom
 - powershell for linux
	 - The script attempts to install it, but I have not been able to test that functionality yet. 

This was built in Ubuntu 18.04 but should work for most linux distros. 
Currently installing powershell for linux is written for Kali (havent tested) but in the future that is going to change. 

    git clone https://github.com/C0ntra99/memInCert
    cd memInCert
    sudo ./main.sh

The first prompt will ask you which IP address you want the metasploit listener and web server to run on (I am used to python and this was the only way I could think of dynamically getting the address).

The next one will ask you which port to listen on, by default it listens on 443.

Finally it asks for the webserver root, in case you aren't running on a Kali install, by default it is /var/www/html.

Once all the prompts go through the script will generate the payload, run invoke-cradlecrafter, craft the certificate, write out the one liner to command.txt, and then start the listener. 
 
 
**The command to run on the target machines is currently written out to command.txt**


*Future plans:*
 - *Add funtionality for cme to allow for automatic shells*
 - *Add support for pwsh on other linux distros*
 - *Add some super cool AsciiArt*
 - *Cleanup stage.ps1*



