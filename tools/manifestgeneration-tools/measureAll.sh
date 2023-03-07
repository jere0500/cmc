#!/bin/bash
if [ ! -d out ]; then
	mkdir out
fi 

measure=1
sign=1
description=1
# n == no measurements
# s == sign everything
# d == create device description
# 	needs pki specified

usage () {
   echo "Usage: $(basename $0) [-nsd]" 2>&1
   echo ' Script to measure all packages of a system installed by the apt package manager'
   echo ' Script depends on apt, apt-rdepends, and jq' 
   echo ' creates out/ for all manifests and out-signed/ for all signed manifests in json format'
   #maybe existance check
   echo ' requires ./dependencies/generateManifest.sh, ./dependencies/signing-tool'
   echo '        ./dependencies/generateManifest.sh also requires ./dependencies/gotouch and ./dependencies/parse-ima-log'
   echo
   echo ' by default collects hashes, generates Manifests, generates device description in out/'
   echo ' by default also signs all manifests to out-signed/'
   echo '    -n  turns off generating appManifests'
   echo '    -s  turns off signing all content of out to out-signed/'
   echo '       if not turned of requires setup of a simple ./pki'
   echo '    -d  turns off creating a device description'
   exit 1
}

while getopts "nsd" opt; do
  case $opt in
    n)
      echo "no measurements"
      measure=0
      ;;
    s)
      echo "sign"
      sign=0
      ;;
    d)
      echo "create device description"
      description=0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
  esac
done

# Measure everything
if [ $measure -eq 1 ]
	then
	tmpf=$(mktemp)
	a=$(mktemp)
	b=$(mktemp)
	cd out

	apt list --installed | awk 'BEGIN {FS="/"};{print $1}' | tail -n +2|sort > $a

	touch ../dependencies
	cat $tmpf

	#find . -maxdepth 2 -mindepth 1  -name '*.manifest.json' |sed s/.\\/out\\///g |sed s/.manifest.json//g | tail -n +2 | sort > $b
	find . -maxdepth 1 -mindepth 1  -name '*.manifest.json' |sed s/.\\///g |sed s/.manifest.json//g| sort > $b



	#cat dependencies >> $a
	#cat $a | sort -u > $tmpf
	#cat $tmpf > $a 
	 
	# all top level
	grep -Fvxf $b $a > $tmpf
	for fn in `cat $tmpf`; do
		echo "the next file is $fn"
		# adding dependencies
		apt-rdepends $fn | grep -v "Depends:\ " | tail -n +2 >> ../deps

		# generate Manifest
		./../dependencies/generateManifest.sh $fn
	done

	# dependencie level
	#find . -maxdepth 2 -mindepth 1  -name '*.manifest.json' |sed s/.\\/out\\///g |sed s/.manifest.json//g | tail -n +2 | sort > $b
	find . -maxdepth 1 -mindepth 1  -name '*.manifest.json' |sed s/.\\///g |sed s/.manifest.json//g| sort > $b

	cat ../deps | sort -u >> $a

	grep -Fvxf $b $a > $tmpf

	cat $tmpf

	for fn in `cat $tmpf`; do
		echo "the next file is $fn"
		./../dependencies/generateManifest.sh $fn
	done


	rm $tmpf
	rm $a
	rm $b
	cd ..
fi

if [ $description -eq 1 ]; then
    tmp1=$(mktemp)
    tmp2=$(mktemp)
    tmpM=$(mktemp)
    files=$(mktemp)
	# runs through all files, gets the name of the app, as well as the filename
	# add the name to a device description array with type App Description
	ls -l out | awk '{print $9}' > $files
	cp template-files/device.description.json $tmp1
 
	for fn in `cat $files`; do
		export fns=$(echo $fn| awk -F. '{print $1}')
		cat out/$fn | jq '.name|{"type":"App Description","name":env.fns, "appManifest":.}' > $tmpM
		jq --slurpfile dd $tmpM '.appDescriptions += $dd' $tmp1 > $tmp2
		#| jq '.appDescriptions += [inputs|.[]] | .' d.d.json # > d.d.2.json
		cp $tmp2 $tmp1
	done

	rm $tmp2
	rm $tmpM
    rm $files
	mv $tmp1 out/device.description.json
fi

# parts from sign simple metadata

if [ $sign -eq 1 ]; then
	PKI="pki"
	INPUT="out"
	OUTPUT="out-signed"
	if [ ! -d $OUTPUT ]; then
		mkdir $OUTPUT
	fi
	KEY=pki/signing-cert-key.pem
	CHAIN=pki/signing-cert.pem,pki/ca.pem

	# getting all files not signed yet

	a=$(mktemp)
	b=$(mktemp)
	tmpf=$(mktemp)
	ls -l out | awk '{print $9}' > $a
	ls -l out-signed | awk '{print $9}' > $b

	grep -Fvxf $b $a > $tmpf
	for fn in `cat $tmpf`; do
		../signing-tool/signing-tool -in $INPUT/$fn -out $OUTPUT/$fn -keys $KEY -x5cs $CHAIN -format json
	done
fi

