// Copyright (c) 2021 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestationreport

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

//structs for additional eventlog content --------------------------------

type ExtendedEventData struct{
	//for certain Uefi variable information events
	uefivariabledata UefiVariableData `json:"uefivariabledata,omitempty" cbor:"0,keyasint,omitempty"`
	//for the GPT_Event
	GPTHeader GPTHeader `json:"gptheader,omitempty" cbor:"1,keyasint,omitempty"`
	//used e.g. for EFI_IPL event
	StringContent string `json:"stringContent,omitempty" cbor:"2,keyasint,omitempty"`
}

type UefiVariableData struct{
	VariableNameGUID string `json:"variablenameguid,omitempty" cbor:"0,keyasint,omitempty"`
	UnicodeName string `json:"unicodename,omitempty" cbor:"1,keyasint,omitempty"`
	
	//can either be variable data (or signature data base)
	variableData []HexByte `json:"variabledata,omitempty" cbor:"2,keyasint,omitempty"`
	signaturedb []SignatureDatabase `json:"signaturedb,omitempty" cbor:"3,keyasint,omitempty"`
}


type SignatureDatabase struct{
	SignatureTypeGUID string `json:"efisignaturelistguid,omitempty" cbor:"0,keyasint,omitempty"`

	//only one of the following per SignatureDataBase
	Certificates []UEFICertificate `json:"ueficertificates,omitempty" cbor:"1,keyasint,omitempty"`
	Sha256Hash []Sha256Hash `json:"sha256hashes,omitempty" cbor:"1,keyasint,omitempty"`
}

type UEFICertificate struct{
	SignatureOwnerGUID string `json:"signatureowneguid,omitempty" cbor:"0,keyasint,omitempty"`
	Certificates  x509.Certificate `json:"certificates,omitempty" cbor:"1,keyasint,omitempty"`
}

type Sha256Hash struct{
	SignatureOwnerGUID string `json:"signatureowneguid,omitempty" cbor:"0,keyasint,omitempty"`
	Sha256Hash []HexByte `json:"sha256,omitempty" cbor:"1,keyasint,omitempty"`
}



type GPTHeader struct {
	Signature                uint64 `json:"signature,omitempty" cbor:"0,keyasint,omitempty"`
	Revision                 uint32 `json:"revision,omitempty" cbor:"1,keyasint,omitempty"`
	HeaderSize               uint32 `json:"headersize,omitempty" cbor:"2,keyasint,omitempty"`
	HeaderCRC32              uint32 `json:"headercrc32,omitempty" cbor:"3,keyasint,omitempty"`
	Reserverd                uint32 `json:"reserved,omitempty" cbor:"4,keyasint,omitempty"`
	MyLBA                    uint64 `json:"mylba,omitempty" cbor:"5,keyasint,omitempty"`
	AlternativeLBA           uint64 `json:"alternativelba,omitempty" cbor:"6,keyasint,omitempty"`
	FirstUsableLBA           uint64 `json:"firstusablelba,omitempty" cbor:"7,keyasint,omitempty"`
	LastUsableLBA            uint64 `json:"lastusablelba,omitempty" cbor:"8,keyasint,omitempty"`
	// DiskGUID1                uint64
	// DiskGUID0                uint64
	DiskGUID			     string `json:"diskguid,omitempty" cbor:"9,keyasint,omitempty"`
	PartitionEntryLBA        uint64 `json:"partitionentrylba,omitempty" cbor:"10,keyasint,omitempty"`
	NumberOfPartitionEntries uint32 `json:"numberofpartitionentries,omitempty" cbor:"11,keyasint,omitempty"`
	SizeOfPartitionEntry     uint32 `json:"sizeofpartitionentry,omitempty" cbor:"12,keyasint,omitempty"`
	PartitionEntryArrayCRC32 uint32 `json:"partitionentryarraycrc32,omitempty" cbor:"13,keyasint,omitempty"`
	Partitions []GPTPartitionEntry `json:"partitions,omitempty" cbor:"13,keyasint,omitempty"`
}

type GPTPartitionEntry struct {
	 // PartitionTypeGUID1   uint64
	 // PartitionTypeGUID0   uint64
	PartitionTypeGUID string `json:"paritiontypeguid,omitempty" cbor:"0,keyasint,omitempty"`
	 // UniquePartitionGUID1 uint64
	 // UniquePartitionGUID0 uint64
	UniquePartitionGUID string `json:"uniquepartitionguid,omitempty" cbor:"0,keyasint,omitempty"`
	StartingLBA          uint64 `json:"startinglba,omitempty" cbor:"0,keyasint,omitempty"`
	EndingLBA            uint64 `json:"endinglba,omitempty" cbor:"0,keyasint,omitempty"`
	Attributes           uint64 `json:"attributes,omitempty" cbor:"0,keyasint,omitempty"`
	ParitionName         string  `json:"partitionname,omitempty" cbor:"0,keyasint,omitempty"` //ParitionName parsed in [36] UTF16
	//no reserved in the exmaple format
}
//--------------------------------------

//TODO insert main function that gets called for each event with the eventbuffer the buffer as parameter and returns an ExtendedEventInformation struct
// func parseAdditionalData (data []ar.ReferenceValue) ExtendedEventInformation {
// 	
// 	for _, value := range data{
// 		//image load event (not supported currently)
// 		// if value.Name == "EV_EFI_BOOT_SERVICES_APPLICATION" || value.Name == "EV_EFI_BOOT_SERVICES_DRIVER" || value.Name == "EV_EFI_RUNTIME_SERVICES_DRIVER" {
//
// 		// }
// 		//for UEFI_VARIABLE_DATA
// 		if value.Name == "EV_EFI_VARIABLE_DRIVER_CONFIG" || value.Name == "EV_EFI_VARIABLE_BOOT" || value.Name == "EV_EFI_VARIABLE_AUTHORITY" {
// 			exInfo := ExtendedEventInformation{}
// 			exInfo.uefivariabledata =  parseUefiVariableData(bytes.NewBuffer(value.AdditionalInfo))
// 			return exInfo
// 		} else if value.Name == "EV_EFI_GPT_EVENT" {
// 			exInfo := ExtendedEventInformation{}
// 			exInfo.GPTHeader =  parseUefiGPTEvent(bytes.NewBuffer(value.AdditionalInfo))
// 			return exInfo
// 		} else if value.Name == "EV_IPL" {
// 			exInfo := ExtendedEventInformation{}
// 			exInfo.StringContent =  bytesToString(value.AdditionalInfo)
// 			return exInfo
// 		}
// 	}
//
// 	return ExtendedEventInformation{}
// }


func parseAdditionalData (eventBytes []uint8, eventName string) ExtendedEventData {
		if eventName == "EV_EFI_VARIABLE_DRIVER_CONFIG" || eventName == "EV_EFI_VARIABLE_BOOT" || eventName == "EV_EFI_VARIABLE_AUTHORITY" {
			exInfo := ExtendedEventData{}
			exInfo.uefivariabledata =  parseUefiVariableData(bytes.NewBuffer(eventBytes))
			return exInfo
		} else if eventName == "EV_EFI_GPT_EVENT" {
			exInfo := ExtendedEventData{}
			exInfo.GPTHeader =  parseUefiGPTEvent(bytes.NewBuffer(eventBytes))
			return exInfo
		} else if eventName == "EV_IPL" {
			exInfo := ExtendedEventData{}
			exInfo.StringContent =  bytesToString(eventBytes)
			return exInfo
		}
	return ExtendedEventData{}
}


//methods for parsing the structures from eventlog data --------------------------------------

//read the GUID from a buffer
func readGUID(buf *bytes.Buffer) string{
	var val1 uint32
	var val2 uint16
	var val3 uint16
	var val4 [2]byte
	var val5 [6]byte

	//reading the values
	binary.Read(buf, binary.LittleEndian, val1)
	binary.Read(buf, binary.LittleEndian, val2)
	binary.Read(buf, binary.LittleEndian, val3)
	binary.Read(buf, binary.LittleEndian, val4)
	binary.Read(buf, binary.LittleEndian, val5)

	output := fmt.Sprintf("%08x",val1)
	output += "-"
	output += fmt.Sprintf("%04x",val2)
	output += "-"
	output += fmt.Sprintf("%04x",val3)
	output += "-"
	output += hex.EncodeToString(val4[:])
	output += "-"
	output += hex.EncodeToString(val5[:])

	return output
}

//simple convert function, that interprets bytes as string (does not dispose)
func bytesToString(uint8Array []uint8) string {
	result := ""
	for _, val := range uint8Array {
		if val < 128 && (val > 27 || (val < 14 && val > 8)) {
			result += string(val)
		} else {
			result += "."
		}
	}
	return result
}

func parseUefiVariableData(buf *bytes.Buffer) UefiVariableData{
	uefiVariableData := UefiVariableData{}

	for buf.Len() >= 32 {
		//TODO checks for not reading to much
		// var variableName0, variableName1, unicodeNameLength, variableDataLength uint64
		var unicodeNameLength, variableDataLength uint64

		//1. part: read binary data into variables
		variableName := readGUID(buf)
		binary.Read(buf, binary.LittleEndian, &unicodeNameLength)
		binary.Read(buf, binary.LittleEndian, &variableDataLength)

		//read the amount of data into the []data fields

		if buf.Len() < 2*int(unicodeNameLength) {
			// return output
			return uefiVariableData
			//TODO throw error
		}


		unicodeName := string(utf16.Decode(make([]uint16, unicodeNameLength)))
		binary.Read(buf, binary.LittleEndian, &unicodeName)

		if buf.Len() < int(variableDataLength) {
			//just stop reading
			return uefiVariableData
		}
		
		//2. part: put data into struct
		uefiVariableData.VariableNameGUID = variableName
		uefiVariableData.UnicodeName = unicodeName

		//parse additional data
		
		if unicodeName == "PK" || unicodeName == "KEK" || unicodeName== "db" || unicodeName== "dbx" { //maybe more
			//parse further
			uefiVariableData.signaturedb = parseEFISignaturedb(buf, int(variableDataLength))
		} else {

			//just add the HexBytes
			variableData := make([]HexByte, variableDataLength)
			binary.Read(buf, binary.LittleEndian, &variableData)
			uefiVariableData.variableData = variableData
		}
	}
	return uefiVariableData
} 

func parseEFISignaturedb(buf *bytes.Buffer, signatureDBSize int) []SignatureDatabase{
	//calculate size of signature Database, and the number of signature dbs
	//signatureDBSize = bytes used in the whole []signaturelist 

	//signature of a single signature in one signature list
	readBytes := 0


	signatureDatabase := make([]SignatureDatabase, 0)
	
	for buf.Len() >= 28 && readBytes < signatureDBSize{ //maybe some size checks
		sigdb := SignatureDatabase{}

		//read the first signatureDatabase
		sigdb.SignatureTypeGUID = readGUID(buf)
		
		var signatureListSize,  signatureHeaderSize, signatureSize      uint32
		binary.Read(buf, binary.LittleEndian, &signatureListSize)
		binary.Read(buf, binary.LittleEndian, &signatureHeaderSize)
		binary.Read(buf, binary.LittleEndian, &signatureSize)

		//countes how often a certificate has been parsed
		counter := 0
		//2nd condition determines if SignatureDB contains multiple Certificates
		certsize := int(signatureSize) - 16
		certs := make([]UEFICertificate, 0) //if they are empty, dispose
		hashes := make([]Sha256Hash, 0) //if they are empty, dispose

		for buf.Len() >= int(signatureSize) && int(signatureListSize)-counter*int(signatureSize) >= int(signatureSize) {
			sigOwner := readGUID(buf)	
			
			//TODO expand to support more types
			//parse only one
			switch(sigdb.SignatureTypeGUID){
				
			case "a5c059a1-94e4-4aa7-87b5-ab155c2bf072":
				cert := UEFICertificate{}
				cert.SignatureOwnerGUID = sigOwner
				cert.Certificates = *parseVariableDataX509_GUID(buf, certsize) 
				certs = append(certs, cert)
			case "c1c41626-504c-4092-aca9-41f936934328":
				hash:= Sha256Hash{}
				hash.SignatureOwnerGUID = sigOwner
				hash.Sha256Hash = parseVariableDataSHA256_GUID(buf)
				hashes = append(hashes, hash)
			}
			//TODO... support more types

		}
		if(len(certs)>0) {sigdb.Certificates = certs}
		if(len(hashes)>0) {sigdb.Sha256Hash = hashes}

		//add the element ot the list
		signatureDatabase = append(signatureDatabase, sigdb)
	}

	return signatureDatabase
}
func parseVariableDataX509_GUID(buf *bytes.Buffer, certsize int) *x509.Certificate {
	certBuf := make([]uint8, certsize)
	cert, err := x509.ParseCertificate(certBuf)
	if err != nil {
		fmt.Println("Failed to parse certificate:", err)
	}
	return cert
}

func parseVariableDataSHA256_GUID(buf *bytes.Buffer) []HexByte {
	sha256buf := make([]HexByte, 32) //sha256 needs 32 bytes
	binary.Read(buf, binary.LittleEndian, sha256buf)
	//todo capture error
	return sha256buf
}

// for UEFI_GPT_EVENT
func parseUefiGPTEvent(buf *bytes.Buffer) GPTHeader{

	//minimum lenght UEFI_PARTITION_TABLE_HEADER = 92 bytes
	for buf.Len() >= 92 {
		partitionTableHeader := GPTHeader{}
		//readall GPTHeader Data
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.Signature)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.Revision)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.HeaderSize)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.HeaderCRC32)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.Reserverd)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.MyLBA)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.AlternativeLBA)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.FirstUsableLBA)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.LastUsableLBA)
		//DiskGUID
		partitionTableHeader.DiskGUID = readGUID(buf)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.PartitionEntryLBA)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.NumberOfPartitionEntries)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.SizeOfPartitionEntry)
		binary.Read(buf, binary.LittleEndian, partitionTableHeader.PartitionEntryArrayCRC32)

		//reading the number of Partitios
		var numberOfPartitions uint64
		binary.Read(buf, binary.LittleEndian, &numberOfPartitions)

		gptPartitions := make([]GPTPartitionEntry, 0)


		//reading the partitions
		if buf.Len() >= int(numberOfPartitions)*128 { //128 Bytes: min size of a GPT Partition Entry
			partition := GPTPartitionEntry{}
			//Partition Type GUID
			partition.PartitionTypeGUID = readGUID(buf)

			//Unique Partition GUID
			partition.UniquePartitionGUID = readGUID(buf)
			binary.Read(buf, binary.LittleEndian, partition.StartingLBA)
			binary.Read(buf, binary.LittleEndian, partition.EndingLBA)
			binary.Read(buf, binary.LittleEndian, partition.Attributes)

			var 	paritionName [36]uint16
			binary.Read(buf, binary.LittleEndian, paritionName)

			partition.ParitionName = string(utf16.Decode(paritionName[:]))

			//appending the partition
			gptPartitions = append(gptPartitions, partition)
		}
		partitionTableHeader.Partitions = gptPartitions

		return partitionTableHeader
	}

	return GPTHeader{}
}

//-------------------------------------
