#!/bin/sh
# $1 = attestation-result.json
# $2 = imalog.json

jqfin=$(mktemp)
imalogtmp=$(mktemp)

# 1st step grep all hashvalues
cat $1 | grep -E "No TPM Reference Value found for TPM measurement:" | sed s/No\ TPM\ Reference\ Value\ found\ for\ TPM\ measurement:\ //g|sed s/\ //g|sed s/\"//g|sed s/,//g | jq -nR '[inputs | {"sha256" : .} ]' > $jqfin

# remove \x
cat $2 | awk '{gsub("\\\\x","/");print}' > $imalogtmp

# 2nd generate json entries
jq --slurpfile list $jqfin --slurpfile log $imalogtmp -n '$list[] | .[] as $listN | $log[] | .[] |select ($listN.sha256 == .sha256)' > e

# add entries to app.manifest.json
jq --slurpfile meas e '.referenceValues += [$meas[]] | .' template-files/app.manifest.json > $jqfin

export appName=$(echo "fixer")
export oMaintain=$(echo "fixer")
export descript=$(echo "generic fix, contains values that have not been captured in manifests")

cat $jqfin | jq --argjson date "$(date --date="6 week ago" +%C%g%m%d000000)" '.validity.notBefore |= ($date|tostring )' | jq --argjson date "$(date --date="6 week" +%C%g%m%d000000)" '.validity.notAfter |= ($date|tostring )' | jq --argjson date "$(date +%C%g%m%d000000)" '.version |= ($date|tostring)' | jq '.name |= env.appName' | jq '.developerCommonName |= env.oMaintain' | jq '.description |= env.descript' > out/fix.manifest.json



rm $jqfin
rm $imalogtmp

