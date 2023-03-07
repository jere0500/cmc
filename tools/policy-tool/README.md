# Shell script to modify policyDeny.js
- requires jq

policyDenyGen.sh
```
     Script to ban or require sha256 values in a policy
     takes 3 arguments:
     $1 needs to be the policyDeny.js
     $2 needs to be an attestation-result.json to search for names hashes
     $3 specifies a pathname in quotes, which is used to look for a hash in the attestation-result.json
     EXAMPLE: ./policyDenyGen.sh -n policyDeny.js attestation-result.json "/usr/bin/bash"
      no flags    add every hash, where the specified pathname is part of a name to the banlist
      -n          also add name to a banlist, which works by name
      -d          does not ban hash, (only useful if -n is specified)
      -c          clear all ban and require lists, before adding new hashes/ names
      -e          use exact matches to the specified pathname instead
      -r          adds the Hash to a requiredHashes list instead (-d is disabled)
```
