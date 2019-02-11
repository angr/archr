Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.define "archr"
  config.vm.provision "shell", inline: <<-SHELL
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    ls -l /vargrant
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!"
    #dpkg --add-architecture i386
    #apt-get update
    #apt-get install -y virtualenvwrapper python3-dev python3-pip build-essential libxml2-dev libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap debian-archive-keyring libglib2.0-dev libpixman-1-dev qtdeclarative5-dev binutils-multiarch nasm libc6:i386 libgcc1:i386 libstdc++6:i386 libtinfo5:i386 zlib1g:i386 vim libssl-dev
    #curl https://get.docker.com | sh
    #useradd -s /bin/bash -m angr
    #adduser angr docker
    #su - angr -c "git clone https://github.com/angr/angr-dev && cd angr-dev && ./setup.sh -w -e angr && ./setup.sh -w -p angr-pypy"
    #su - angr -c "echo 'workon angr' >> /home/angr/.bashrc"
  SHELL
end
