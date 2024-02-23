// Copyright (c) 2024 Fraunhofer AISEC
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

package attestedtls

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

const REATTEST_AFTER_TIME = 30 * time.Second //after 30 seconds do reattestation
const GRACE_PERIOD = 5 * time.Second         //seconds, where bytes are still passed after reattestation is due

type Conn struct {
	//wrapper for net.Conn
	Conn            net.Conn
	lastAttestation time.Time

	//for invoking reattestation
	isDialer   bool
	cc         CmcConfig
	chbindings []byte

	//to prevent spamming attestation reports
	sentReattest bool

	//?maybe additional attributs
	//?the two timer layouts
}

// Write implements net.Conn.
func (c *Conn) Write(b []byte) (n int, err error) {
	
	if time.Now().After(c.lastAttestation.Add(REATTEST_AFTER_TIME + GRACE_PERIOD)){
		return -1, fmt.Errorf("no reattestation received, terminate connnection")
	}

	if time.Now().After(c.lastAttestation.Add(REATTEST_AFTER_TIME)){
		//do reattestation if (necessary)
		initiateReattest(c)
		if err != nil {
			//still forwarding the byte
			log.Debug(err)
		}
	}

	return c.Conn.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	out, err := c.Conn.Read(b)
	if time.Now().After(c.lastAttestation.Add(REATTEST_AFTER_TIME + GRACE_PERIOD)){
		return -1, fmt.Errorf("no reattestation received, terminate connnection")
	}

	if time.Now().After(c.lastAttestation.Add(REATTEST_AFTER_TIME)){
		//do reattestation if (necessary)
		initiateReattest(c)
		if err != nil {
			//still forwarding the byte
			return out, err
		}
	}

	//check for any incomming attestation reports
	ret := bytes.Index(b, ATLS_MAGIC_VALUE[:])
	if ret != -1 {
		// buffer contains the magic value
		report, err := readValue(b[ret:], c.cc.Attest, c.isDialer, c.cc)
		if err != nil {
			if strings.Contains("could not unmarshal atls response", err.Error()) {
				//invalid cbor serialization
				//continue
				log.Trace(err)
			} else {
				//? should probably terminate the connection
				log.Tracef("invalid attestation report: %v", err)
				return -1, err
			}
		} else {
			//verify the attestation report
			validateAttestationReport(c.chbindings, c.cc, report, c.isDialer)

			//sucessfull received and validated attestation report
			c.lastAttestation = time.Now()
			c.sentReattest = false
		}

	}

	return out, err
}

func initiateReattest(c *Conn) error {
	//against spamming
	if c.sentReattest == true {
		return nil
	}

	//do reattestation if (necessary)
	err := sendAttestationReport(c.Conn, c.chbindings, c.cc, c.isDialer)
	if err != nil {
		//still forwarding the byte
		return err
	}
	c.sentReattest = true

	return nil
}

// boilerplate code
func (c *Conn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)

}
func (c *Conn) Close() error {
	return c.Conn.Close()
}

//? probably need to add the other boilerplate methods
