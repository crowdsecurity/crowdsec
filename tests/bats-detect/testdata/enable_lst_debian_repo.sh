#!/bin/bash


if [ -r /etc/os-release ]; then

	echo " detecting OS type : "

	. /etc/os-release

	if [ $ID == "debian" ]; then
		echo "detected OS: $ID - $VERSION_ID"
		echo " now enable the LiteSpeed Debian Repo "
		if [ $VERSION_ID == "11" ]; then	
                        echo "deb http://rpms.litespeedtech.com/debian/ bullseye main" > /etc/apt/sources.list.d/lst_debian_repo.list
                        echo "#deb http://rpms.litespeedtech.com/edge/debian/ bullseye main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		elif [ $VERSION_ID == "10" ]; then	
                        echo "deb http://rpms.litespeedtech.com/debian/ buster main" > /etc/apt/sources.list.d/lst_debian_repo.list
                        echo "#deb http://rpms.litespeedtech.com/edge/debian/ buster main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		elif [ $VERSION_ID == "9" ]; then
                        echo "deb http://rpms.litespeedtech.com/debian/ stretch main" > /etc/apt/sources.list.d/lst_debian_repo.list
                        echo "#deb http://rpms.litespeedtech.com/edge/debian/ stretch main" >> /etc/apt/sources.list.d/lst_debian_repo.list
                elif [ $VERSION_ID == "8" ]; then
			echo "deb http://rpms.litespeedtech.com/debian/ jessie main" > /etc/apt/sources.list.d/lst_debian_repo.list
			echo "#deb http://rpms.litespeedtech.com/edge/debian/ jessie main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		fi
	elif [ $ID == "ubuntu" ]; then
		echo "detected OS: $ID - $VERSION_ID"
		echo " now enable the LiteSpeed Debian Repo "
		if [ `echo "$VERSION_ID" | cut -b-2 ` == "14" ]; then
			echo "deb http://rpms.litespeedtech.com/debian/ trusty main" > /etc/apt/sources.list.d/lst_debian_repo.list
			echo "#deb http://rpms.litespeedtech.com/edge/debian/ trusty main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		elif [ `echo "$VERSION_ID" | cut -b-2 ` == "12" ]; then
			echo "deb http://rpms.litespeedtech.com/debian/ precise main" > /etc/apt/sources.list.d/lst_debian_repo.list
			echo "#deb http://rpms.litespeedtech.com/edge/debian/ precise main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		elif [ `echo "$VERSION_ID" | cut -b-2 ` == "16" ]; then
			echo "deb http://rpms.litespeedtech.com/debian/ xenial main" > /etc/apt/sources.list.d/lst_debian_repo.list
			echo "#deb http://rpms.litespeedtech.com/edge/debian/ xenial main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		elif [ `echo "$VERSION_ID" | cut -b-2 ` == "18" ]; then
			echo "deb http://rpms.litespeedtech.com/debian/ bionic main" > /etc/apt/sources.list.d/lst_debian_repo.list
			echo "#deb http://rpms.litespeedtech.com/edge/debian/ bionic main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		elif [ `echo "$VERSION_ID" | cut -b-2 ` == "20" ]; then
			echo "deb http://rpms.litespeedtech.com/debian/ focal main" > /etc/apt/sources.list.d/lst_debian_repo.list
			echo "#deb http://rpms.litespeedtech.com/edge/debian/ focal main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		elif [ `echo "$VERSION_ID" | cut -b-2 ` == "22" ]; then
			echo "deb http://rpms.litespeedtech.com/debian/ focal main" > /etc/apt/sources.list.d/lst_debian_repo.list
			echo "#deb http://rpms.litespeedtech.com/edge/debian/ focal main" >> /etc/apt/sources.list.d/lst_debian_repo.list
		fi
	else
		echo " This distribution is not currently supported by LST repo "
		echo " If you really have the needs please contact LiteSpeed for support "
	fi
else
	echo " The /etc/os-release file doesn't exist "
	echo " This script couldn't determine which distribution of the repo should be enabled "
	echo " Please consult LiteSpeed Customer Support for further assistance "
fi

echo " register LiteSpeed GPG key "
wget -O /etc/apt/trusted.gpg.d/lst_debian_repo.gpg http://rpms.litespeedtech.com/debian/lst_debian_repo.gpg
wget -O /etc/apt/trusted.gpg.d/lst_repo.gpg http://rpms.litespeedtech.com/debian/lst_repo.gpg

echo " update the repo "
apt-get update

echo " All done, congratulations and enjoy ! "
