package gootp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

func hmacMsg(c, key []byte, h func() hash.Hash) ([]byte, error) {
	//Hash the message derived from the time with the key from the TOTP secret
	mac := hmac.New(h, key)
	_, err := mac.Write(c)
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

func generateHashCountFromTime(t time.Time) ([]byte, error) {
	//The message to be hashed is the count of the number of time intervals
	c := t.Unix() / 30
	return generateHashCount(c)
}

func generateHashCount(c int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, c)
	if err != nil {
		return make([]byte, 0), err
	}
	return buf.Bytes(), nil
}

func extractFromHash(hash []byte) uint32 {
	//Get the last 4 bits of the hash (a value ranging from 0-15)
	// This will be the index into the 20-byte value
	iBits := hash[len(hash)-1] & 0xf
	iInt := int64(iBits)

	//Extract the next 4 bytes starting at the index and convert to uint32
	r := bytes.NewReader(hash)
	var b [4]byte
	r.ReadAt(b[:], iInt)
	b[0] = b[0] & 0x7f
	return binary.BigEndian.Uint32(b[:])
}

func GetHOTP(secret string, count int64, mode func() hash.Hash, digits int) (otp string, err error) {
	key, err := generateHashKey(secret)
	if err != nil {
		return
	}
	msg, err := generateHashCount(count)
	if err != nil {
		return
	}
	if mode == nil {
		mode = sha1.New
	}
	hash, err := hmacMsg(msg, key, mode)
	if err != nil {
		return
	}
	otpInt := int(math.Mod(float64(extractFromHash(hash)), math.Pow(10, float64(digits))))
	otp = fmt.Sprintf("%0"+strconv.Itoa(digits)+"d", otpInt)
	return
}

func GetTOTPNow(secret string, mode func() hash.Hash, digits int) (otp string, timeRemaining int, err error) {
	otp, timeRemaining, err = GetTOTPAt(secret, time.Now().UTC(), mode, digits)
	return
}

func GetTOTPAt(secret string, t time.Time, h func() hash.Hash, digits int) (otp string, timeRemaining int, err error) {
	key, err := generateHashKey(secret)
	if err != nil {
		return "", 0, err
	}
	msg, err := generateHashCountFromTime(t)
	if err != nil {
		return "", 0, err
	}
	hash, err := hmacMsg(msg, key, h)
	if err != nil {
		return "", 0, err
	}
	timeRemaining = int(30 - math.Mod(float64(t.Unix()), 30))
	otpInt := int(math.Mod(float64(extractFromHash(hash)), math.Pow(10, float64(digits))))
	otp = fmt.Sprintf("%0"+strconv.Itoa(digits)+"d", otpInt)
	return
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateOTPSecret(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base32.StdEncoding.EncodeToString(b), err
}
