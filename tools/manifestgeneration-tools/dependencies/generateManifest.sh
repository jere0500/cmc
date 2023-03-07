#!/bin/sh
tmpf=$(mktemp)
# out=$(mktemp)
imaLogTemp=$(mktemp)
jqfin=$(mktemp)
appM=$(mktemp)

dpkg -L $1 | sort -u | xargs realpath > $tmpf
cat $tmpf | xargs sudo ./../dependencies/gotouch 
cat $tmpf | sed s/\ /\\n/g | jq -nR '[inputs | {"name" : . } ]' > $jqfin

sudo parse-ima-log | awk '{gsub("\\\\x","/");print}' > $imaLogTemp

jq --slurpfile list $jqfin --slurpfile log $imaLogTemp -n '$list[] | .[] as $listN |  $log[]| .[] | select ($listN.name == .name)' > $tmpf
jq --slurpfile meas $tmpf '.referenceValues += [$meas[]] | .' ../template-files/app.manifest.json > $appM

apt info $1 > $tmpf
# export appName=$(cat $tmpf | awk '{if($1=="Homepage:"){print $0}}' | sed s/Homepage\:\ https*:\\/\\///g | sed s/\ /\_/g)
export appName=$(echo -n $1'.';hostname -s)
export oMaintain=$(cat $tmpf | awk '{if($1=="Original-Maintainer:"){print $0}}' | sed s/Original-Maintainer\:\ \//g)
export descript=$(cat $tmpf | awk '{if($1=="Description:"){print $0}}' | sed s/Description\:\ //g)
cat $appM | jq --argjson date "$(date --date="6 week ago" +%C%g%m%d000000)" '.validity.notBefore |= ($date|tostring )' | jq --argjson date "$(date --date="6 week" +%C%g%m%d000000)" '.validity.notAfter |= ($date|tostring )' | jq --argjson date "$(date +%C%g%m%d000000)" '.version |= ($date|tostring)' | jq '.name |= env.appName' | jq '.developerCommonName |= env.oMaintain' | jq '.description |= env.descript' > $1.manifest.json
rm $appM

rm $tmpf
rm $imaLogTemp
rm $jqfin
