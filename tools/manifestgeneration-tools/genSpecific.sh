#!/bin/sh
tmpf=$(mktemp)
# out=$(mktemp)
imaLogTemp=$(mktemp)
jqfin=$(mktemp)
appM=$(mktemp)

# $1 is the name of the manifest
# $2 is the path 

usage () {
      echo "Usage: $(basename $0) \"nameofmanifest\" /path/to/measure/ " 2>&1
      echo 'measures all files in a specified path and puts the measurements into an appManifest based on the specified manifestname'
}

if [ "$#" -ne 2 ]; then
    echo "wrong number of operands"
    usage
    exit 1
fi


if [ ! -d out ]; then
        mkdir out
fi
cd out

find $2 |  xargs realpath > $tmpf
cat $tmpf | xargs sudo ./../gotouch 
cat $tmpf | sed s/\ /\\n/g | jq -nR '[inputs | {"name" : . } ]' > $jqfin
cat $jqfin

sudo ./../dependencies/parse-ima-log | awk '{gsub("\\\\x","/");print}' > $imaLogTemp

jq --slurpfile list $jqfin --slurpfile log $imaLogTemp -n '$list[] | .[] as $listN |  $log[]| .[] | select ($listN.name == .name)' > $tmpf
jq --slurpfile meas $tmpf '.verifications += [$meas[]] | .' ../template-files/app.manifest.json > $appM


# apt info $1 > $tmpf
# export appName=$(cat $tmpf | awk '{if($1=="Homepage:"){print $0}}' | sed s/Homepage\:\ https*:\\/\\///g | sed s/\ /\_/g)
export appName=$2
# export oMaintain=$(cat $tmpf | awk '{if($1=="Original-Maintainer:"){print $0}}' | sed s/Original-Maintainer\:\ \//g)
# export descript=$(cat $tmpf | awk '{if($1=="Description:"){print $0}}' | sed s/Description\:\ //g)
cat $appM | jq --argjson date "$(date --date="6 week ago" +%C%g%m%d000000)" '.validity.notBefore |= ($date|tostring)' | jq --argjson date "$(date --date="6 week" +%C%g%m%d000000)" '.validity.notAfter |= ($date|tostring)' | jq --argjson date "$(date +%C%g%m%d000000)" '.version |= ($date|tostring)' | jq '.name |= env.appName' > $1.manifest.json
rm $appM

rm $tmpf
rm $imaLogTemp
rm $jqfin
