// Package fec implements Reed Solomon 9/3 forward error correction,
//  intended to be sent as 9 pieces where 3 uncorrupted parts allows assembly of the message
package fec

import (
	"encoding/binary"

	log "github.com/p9c/logi"
	"github.com/vivint/infectious"
)

var (
	rsTotal    = 9
	rsRequired = 3
	rsFEC      = func() *infectious.FEC {
		fec, err := infectious.NewFEC(rsRequired, rsTotal)
		if err != nil {
			log.L.Error(err)
		}
		return fec
	}()
)

// padData appends a 2 byte length prefix, and pads to a multiple of rsTotal.
// Max message size is limited to 1<<32 but in our use will never get near
// this size through higher level protocols breaking packets into sessions
func padData(data []byte) (out []byte) {
	dataLen := len(data)
	prefixBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(prefixBytes, uint32(dataLen))
	data = append(prefixBytes, data...)
	dataLen = len(data)
	chunkLen := (dataLen) / rsTotal
	chunkMod := (dataLen) % rsTotal
	if chunkMod != 0 {
		chunkLen++
	}
	padLen := rsTotal*chunkLen - dataLen
	out = append(data, make([]byte, padLen)...)
	return
}

// Encode turns a byte slice into a set of shards with first byte containing
// the shard number. Previously this code included a CRC32 but this is
// unnecessary since the shards will be sent wrapped in HMAC protected
// encryption
func Encode(data []byte) (chunks [][]byte, err error) {
	// First we must pad the data
	data = padData(data)
	shares := make([]infectious.Share, rsTotal)
	output := func(s infectious.Share) {
		shares[s.Number] = s.DeepCopy()
	}
	err = rsFEC.Encode(data, output)
	if err != nil {
		log.L.Error(err)
		return
	}
	for i := range shares {
		// Append the chunk number to the front of the chunk
		chunk := append([]byte{byte(shares[i].Number)}, shares[i].Data...)
		// Checksum includes chunk number byte so we know if its checksum is
		// incorrect so could the chunk number be
		// checksum := crc32.Checksum(chunk, crc32.MakeTable(crc32.Castagnoli))
		// checkBytes := make([]byte, 4)
		// binary.LittleEndian.PutUint32(checkBytes, checksum)
		// chunk = append(chunk, checkBytes...)
		chunks = append(chunks, chunk)
	}
	// log.L.Spew(chunks)
	return
}

func Decode(chunks [][]byte) (data []byte, err error) {
	var shares []infectious.Share
	for i := range chunks {
		// bodyLen := len(chunks[i])
		// log.L.Spew(chunks[i])
		body := chunks[i] // [:bodyLen]
		share := infectious.Share{
			Number: int(body[0]),
			Data:   body[1:],
		}
		shares = append(shares, share)
	}
	data, err = rsFEC.Decode(nil, shares)
	if len(data) > 4 {
		prefix := data[:4]
		data = data[4:]
		dataLen := int(binary.LittleEndian.Uint32(prefix))
		data = data[:dataLen]
	}
	return
}
