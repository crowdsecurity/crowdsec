#!/bin/bash
#find . -name "*"deb -exec dpkg-sig -k 76BB08A3995DD598484A0CE6F275830D0D012898 -p --sign builder {} \;

aws s3 sync s3://crowdsec.packaging.assets/debian/packages /tmp/packages --delete --profile consensus

cd /tmp/packages

for i in buster stretch bullseye bionic sid focal xenial
do
    cd $i
    mkdir -p conf
    echo "Origin: Crowdsec" > conf/distributions
    echo "Label: Crowdsec" >> conf/distributions
    echo "Codename: $i" >> conf/distributions
    echo "Architectures: i386 amd64 arm64" >> conf/distributions
    echo "Components: main" >> conf/distributions
    echo "Description: Apt repository for project crowdsec" >> conf/distributions
    echo "SignWith: 76BB08A3995DD598484A0CE6F275830D0D012898" >> conf/distributions

    
    #find . -name "*"deb -exec reprepro -S base -P 500 includedeb $i {}  \;
    for file in $(ls *.deb) ; do reprepro -S base -P 800 includedeb $i $file && rm -f $file ; done
    
    cd ..
    #aws s3api put-object --acl private --bucket crowdsec.debian.pragmatic --key $i/conf/distributions --body conf/distributions --profile consensus
done

#aws s3 sync . s3://crowdsec.debian.pragmatic  --delete --exclude "*".db --exclude distributions --profile consensus
#aws s3 sync /tmp/packages s3://crowdsec.packaging.assets/debian/packages --delete  --profile consensus
