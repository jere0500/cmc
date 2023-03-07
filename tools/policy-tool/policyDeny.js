// Parse the verification result
var obj = JSON.parse(json);
var success = true;

//required Paths in the AppManifests
requirePaths = ["/usr/bin/setxkbmap", "/usr/sbin/iptables-apply", "/usr/sbin/update-grub"];
//forbidden Paths in the AppManifests
forbiddenPaths = ["/usr/bin/virus"];

//forbidden Hashes
// namesToHashe = []
forbiddenHashes = [ ]

//required Hashes
requiredHashes = [ ]



var requirePathsFound = new Array(requirePaths.length);
var requiredHashesFound = new Array(requirePaths.length);
var forbiddenPathsFound = new Array(forbiddenPaths.length);
var forbiddenHashesFound = new Array(forbiddenHashes.length);

// Basic checks
// if (obj.type != "Verification Result") {
//     console.log("Invalid type");
//     success = false;
// }
// if (!obj.raSuccessful) {
//     console.log("Attestation not sucessful")
//     success = false;
// }
//
// // Check a certain certificate property in the RTM Manifest
// var found = false
// for (var i = 0; i < obj.rtmValidation.signatureValidation.length; i++) {
//     if (obj.rtmValidation.signatureValidation[i].commonName == "CMC Test Leaf Certificate") {
//         found = true;
//     }
// }
// if (!found) {
//     console.log("Failed to find certificate 'CMC Test Leaf Certificate'");
//     success = false;
// }

// Check the file and deny a specific pathname
//try1: with fs
// obj.validatedAttestationReport.appManifests[].referenceValues[].name == "/etc/example/path"
//
//check the required Hashes
//should be at obj.validatedAttestationReport.tpmMeasurement.hashChain[].sha256[]
foundall = false
for (var i = 0; i < obj.validatedAttestationReport.tpmMeasurement.hashChain.length; i++) {
if(obj.validatedAttestationReport.tpmMeasurement.hashChain[i].pcr == 10){
        for (var j = 0; j < obj.validatedAttestationReport.tpmMeasurement.hashChain[i].sha256.length; j++) {
            for (var k = 0; k < requiredHashes.length; k++){
                if(obj.validatedAttestationReport.tpmMeasurement.hashChain[i].sha256[j] == requiredHashes[k]){
                    requiredHashesFound[k] = true;
                }
            }
        }
    }
}

for (var i = 0; i < requiredHashesFound.length; i++){
    if(!requiredHashesFound[i]){foundall = false;}
}
if (!foundall) {
    console.log("Specific required Hash not found");
    success = false;
}

if(success) {
//requirelist
    found = true
    for (var i = 0; i < obj.validatedAttestationReport.appManifests.length; i++) {
        for (var j = 0; j < obj.validatedAttestationReport.appManifests[i].referenceValues.length; j++) {
            for (var k = 0; k < requirePaths.length; k++){
                if(obj.validatedAttestationReport.appManifests[i].referenceValues[j].name == requirePaths[k]){
                    requirePathsFound[k] = true;
                }
            }
        }
    }

    for (var i = 0; i < requirePathsFound.length; i++){
        if(!requirePathsFound[i]){found = false;}
    }
    if (!found) {
        console.log("Allowed Path not found");
        success = false;
    }
}

//only if not yet failed
if(success) {
    //denyList
    found = false
    for (var i = 0; i < obj.validatedAttestationReport.appManifests.length; i++) {
        for (var j = 0; j < obj.validatedAttestationReport.appManifests[i].referenceValues.length; j++) {
            for (var k = 0; k < forbiddenPaths.length; k++){
                if(obj.validatedAttestationReport.appManifests[i].referenceValues[j].name == forbiddenPaths[k]){
                    forbiddenPathsFound[k] = true;
                }
            }
        }
    }

    for (var i = 0; i < forbiddenPathsFound.length; i++){
        if(forbiddenPathsFound[i]){found = true;}
    }

    if (found) {
        console.log("Forbidden Path Found");
        success = false;
    }
}

// check forbiddenHashes
if (success){
    found = false
    for (var i = 0; i < obj.validatedAttestationReport.appManifests.length; i++) {
        for (var j = 0; j < obj.validatedAttestationReport.appManifests[i].referenceValues.length; j++) {
            for (var k = 0; k < forbiddenHashes.length; k++){
                if(obj.validatedAttestationReport.appManifests[i].referenceValues[j].sha256 == forbiddenHashes[k]){
                    forbiddenHashesFound[k] = true;
                }
            }
        }
    }

    for (var i = 0; i < forbiddenHashesFound.length; i++){
        if(forbiddenHashesFound[i]){found = true;}
    }

    if (found) {
        console.log("Forbidden Hash Found");
        success = false;
    }

}


success
