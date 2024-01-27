FROM --platform=linux/amd64 ubuntu:focal
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential openssh-server vim
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y strace
RUN mkdir /var/run/sshd
RUN echo 'root:toor' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
CMD ["/usr/sbin/sshd","-d"]
