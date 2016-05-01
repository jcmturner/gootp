package gootp

import (
	"bytes"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

func hmacMsg(count, key []byte, mode func() hash.Hash) ([]byte, error) {
	//Hash the message derived from the time with the key from the TOTP secret
	mac := hmac.New(mode, key)
	_, err := mac.Write(count)
	if err != nil {
		return make([]byte, 0), err
	}
	return mac.Sum(nil), nil
}

func generateHashKey(s string) ([]byte, error) {
	//Decode and convert the base32 encoded secret string to a byte array
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(s))
	if err != nil {
		return make([]byte, 0), err
	}
	return key, nil
}

func generateHashCountFromTime(time time.Time) ([]byte, error) {
	//The message to be hashed is the number of intervals
	numberIntervals := time.Unix() / 30
	return generateHashCount(numberIntervals)
}

func generateHashCount(count int64) ([]byte, error) {
	intervalsBuf := new(bytes.Buffer)
	err := binary.Write(intervalsBuf, binary.BigEndian, count)
	if err != nil {
		return make([]byte, 0), err
	}
	return intervalsBuf.Bytes(), nil
}

func extractFromHash(hash []byte) uint32 {
	//Get the last 4 bits of the hash (a value ranging from 0-15)
	// This will be the index into the 20-byte value
	indexBits := hash[len(hash)-1] & 0xf
	indexInt := int64(indexBits)

	//Extract the next 4 bytes starting at the index and convert to uint32
	hashReader := bytes.NewReader(hash)
	var fourbytes [4]byte
	hashReader.ReadAt(fourbytes[:], indexInt)
	fourbytes[0] = fourbytes[0] & 0x7f
	return binary.BigEndian.Uint32(fourbytes[:])
}

func GetHOTP(secret string, count int64, mode func() hash.Hash, digits int) (string, error) {
	key, err := generateHashKey(secret)
	if err != nil {
		return "", err
	}
	msg, err := generateHashCount(count)
	if err != nil {
		return "", err
	}
	hash, err := hmacMsg(msg, key, mode)
	if err != nil {
		return "", err
	}
	otpInt := int(math.Mod(float64(extractFromHash(hash)), math.Pow(10, float64(digits))))
	return fmt.Sprintf("%0"+strconv.Itoa(digits)+"d", otpInt), nil
}

func GetTOTPNow(secret string, mode func() hash.Hash, digits int) (string, int, error) {
	return GetTOTPAt(secret, time.Now().UTC(), mode, digits)
}

func GetTOTPAt(secret string, time time.Time, mode func() hash.Hash, digits int) (string, int, error) {
	key, err := generateHashKey(secret)
	if err != nil {
		return "", 0, err
	}
	msg, err := generateHashCountFromTime(time)
	if err != nil {
		return "", 0, err
	}
	hash, err := hmacMsg(msg, key, mode)
	if err != nil {
		return "", 0, err
	}
	timeRemaining := 30 - math.Mod(float64(time.Unix()), 30)
	otpInt := int(math.Mod(float64(extractFromHash(hash)), math.Pow(10, float64(digits))))
	return fmt.Sprintf("%0"+strconv.Itoa(digits)+"d", otpInt), int(timeRemaining), nil
}
