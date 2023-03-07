#!/bin/bash
# $1 == policyDeny.js
# $2 == attestation-result.json
#
# flags:
# -n: ban also name
name=0
# -h: dont ban hash
hash=1
# -c: clear hash; terminate
clear=0
# -r: clear hash; terminate
require=0

usage() {
    echo "Usage: $(basename $0) [-ndcer] policyDeny.js attestation-result.json \"/path/to/match\" "  2>&1
    echo ' Script to ban or require sha256 values in a policy'
    echo ' $1 needs to be the policyDeny.js'
    echo ' $2 needs to be an attestation-result.json to search for names hashes'
    echo ' $3 specifies a pathname in quotes, which is used to look for a hash in the attestation-result.json'
    echo ' EXAMPLE: ./policyDenyGen.sh -n policyDeny.js attestation-result.json "/usr/bin/bash"'
    echo 
    echo '  no flags    add every hash, where the specified pathname is part of a name to the banlist'
    echo '  -n          also add name to a banlist, which works by name'
    echo '  -d          does not ban hash, (only useful if -n is specified)'
    echo '  -c          clear all ban and require lists, before adding new hashes/ names'
    echo '  -e          use exact matches to the specified pathname instead'
    echo '  -r          adds the Hash to a requiredHashes list instead (-d is disabled)'
    exit 1
}

exact=0
while getopts "ndcer" opt; do
  case $opt in
    n)
      echo "also add name to banlist"
      name=1
      ;;
    d)
      echo "dont ban hash"
      hash=0
      ;;
    c)
      echo "clear all banlists, then terminate"
      clear=1
      ;;
    e)
        echo "only exact matches to the path-string"
        exact=1
        ;;
    r)
      echo "require add hash to a require list instead of a banlist"
      require=1
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
  esac
done

# allignes the input parameters
shift $(($OPTIND - 1))

if [ "$#" -lt 2 ]; then
    echo "missing parameters"
    usage
fi

if [ $clear -eq 1 ]; then
      sed -r -i s/forbiddenHashes\ =\ .+$/forbiddenHashes\ =\ \\\[\ \]/ $1
      sed -r -i s/forbiddenPaths\ =\ .+$/forbiddenPaths\ =\ \\\[\ \]/ $1
      sed -r -i s/requiredHashes\ =\ .+$/requiredHashes\ =\ \\\[\ \]/ $1
      if [ $hash -eq 0]; then
          exit 0
      fi
fi

if [ "$#" -lt 3 ]; then
    echo "missing parameters"
    usage
fi

if [ $require -eq 1 ]; then
    # gets all the Hashes separated by comma
    export currentHashes=$(grep -E 'requiredHashes = ' $1 | sed s/requiredHashes\ =\ //g | sed 's/.//;s/.$//')

    export ENV=$(echo $3)
    echo $ENV
    # find a hash by path in an attestation-result //paths noch austauschen
    if [ $exact -eq 1 ]; then
        export hash=$(jq '.validatedAttestationReport.appManifests[].referenceValues[] | select (.name == env.ENV) | .sha256' $2 | sort -u | paste -sd "," -)
    else
        export hash=$(jq '.validatedAttestationReport.appManifests[].referenceValues[] | select (.name | contains(env.ENV)) | .sha256' $2 | sort -u | paste -sd "," -)
    fi
    echo $hash
    # but new Hashes into place
    if [ "$currentHashes" = " " ]
    then
        export newHashes=$(echo $hash)
    else
        export newHashes=$(echo $currentHashes,$hash)
    fi 
    sed -r -i s/requiredHashes\ =\ .+$/requiredHashes\ =\ \\\[$newHashes\]/ $1
    # done with the script
    exit 0
fi

if [ $name -eq 1 ]; then
    export currentPaths=$(grep -E 'forbiddenPaths = ' $1 | sed s/forbiddenPaths\ =\ //g | sed 's/.//;s/.$//')

    # Path to add
    
    if [ "$currentPaths" = " " ]
    then
        export newPaths=$(echo \"$3\")
    else
        export newPaths=$(echo $currentPaths,\"$3\")
    fi 
    echo $1
    echo $newPaths
    sed -r -i s:forbiddenPaths\ =\ .+$:forbiddenPaths\ =\ \\\[$newPaths\]: $1
fi

if [ $hash -eq 1 ]; then
    # gets all the Hashes separated by comma
    export currentHashes=$(grep -E 'forbiddenHashes = ' $1 | sed s/forbiddenHashes\ =\ //g | sed 's/.//;s/.$//')

    export ENV=$(echo $3)
    echo $ENV
    # find a hash by path in an attestation-result //paths noch austauschen
    if [ $exact -eq 1 ]; then
        export hash=$(jq '.validatedAttestationReport.appManifests[].referenceValues[] | select (.name == env.ENV) | .sha256' $2 | sort -u | paste -sd "," -)
    else
        export hash=$(jq '.validatedAttestationReport.appManifests[].referenceValues[] | select (.name | contains(env.ENV)) | .sha256' $2 | sort -u | paste -sd "," -)
    fi
    echo $hash
    # but new Hashes into place
    if [ "$currentHashes" = " " ]
    then
        export newHashes=$(echo $hash)
    else
        export newHashes=$(echo $currentHashes,$hash)
    fi 
    sed -r -i s/forbiddenHashes\ =\ .+$/forbiddenHashes\ =\ \\\[$newHashes\]/ $1
fi
