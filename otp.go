package gootp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
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

/*
Get the HMAC-based One Time Password (RFC 4226). Providing the following inputs:
	- Secret string at least 16 bytes / 128 bits in length
	- Counter value, the moving factor (see RFC 4226 section 5.2).  This counter MUST be synchronized between the HOTP generator (client) and the HOTP validator (server).
	- A hash function to use, eg SHA1, SHA256, SHA512
	- The number of digits to be returned in the OTP. Must be a minimum of 6.

Note that the returned OTP is a string as a leading zero is valid so an integer type is not appropriate
*/
func GetHOTP(secret string, count int64, mode func() hash.Hash, digits int) (otp string, err error) {
	if digits < 6 {
		err = errors.New("The number of digits of the OTP generated must be at least 6")
		return
	}
	if len(secret) < 16 {
		err = errors.New("The secret string used to generate the OTP must be at least 128 bits")
		return
	}
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

/*
Get the Time-based One Time Password (RFC 6238) for the current time. Providing the following inputs:
	- Secret string at least 16 bytes / 128 bits in length.
	- A hash function to use, eg SHA1, SHA256, SHA512.
	- The number of digits to be returned in the OTP. Must be a minimum of 6.

Note that the returned OTP is a string as a leading zero is valid so an integer type is not appropriate.
The number of seconds the OTP is valid for is also returned.
*/
func GetTOTPNow(secret string, mode func() hash.Hash, digits int) (otp string, timeRemaining int, err error) {
	otp, timeRemaining, err = GetTOTPAt(secret, time.Now().UTC(), mode, digits)
	return
}

/*
Get the Time-based One Time Password (RFC 6238) for a specific time. Providing the following inputs:
	- Secret string at least 16 bytes / 128 bits in length.
	- The UTC time for which the TOTP should be generated.
	- A hash function to use, eg SHA1, SHA256, SHA512.
	- The number of digits to be returned in the OTP. Must be a minimum of 6.

Note that the returned OTP is a string as a leading zero is valid so an integer type is not appropriate.
The number of seconds the OTP is valid for is also returned.
*/
func GetTOTPAt(secret string, t time.Time, h func() hash.Hash, digits int) (otp string, timeRemaining int, err error) {
	key, err := generateHashKey(secret)
	if err != nil {
		return
	}
	msg, err := generateHashCountFromTime(t)
	if err != nil {
		return
	}
	hash, err := hmacMsg(msg, key, h)
	if err != nil {
		return
	}
	timeRemaining = int(30 - math.Mod(float64(t.Unix()), 30))
	otpInt := int(math.Mod(float64(extractFromHash(hash)), math.Pow(10, float64(digits))))
	otp = fmt.Sprintf("%0"+strconv.Itoa(digits)+"d", otpInt)
	return
}

/*
Get a Time-based One Time Password history (RFC 6238). Providing the following inputs:
 - Secret string at least 16 bytes / 128 bits in length.
 - A hash function to use, eg SHA1, SHA256, SHA512.
 - The number of digits to be returned in the OTP. Must be a minimum of 6.

Note that the returned OTP is an array of strings as a leading zero is valid so an integer type is not appropriate. The first element in the array is the current OTP.
The number of seconds the current OTP is valid for is also returned.
*/
func GetTOTPHistory(secret string, h func() hash.Hash, digits int, history int) (otps []string, timeRemaining int, err error) {
	key, err := generateHashKey(secret)
	if err != nil {
		return
	}
	c := time.Now().UTC().Unix() / 30
	timeRemaining = int(30 - math.Mod(float64(time.Now().UTC().Unix()), 30))
	for i := 0; i < history; i++ {
		c = c - int64(i)
		msg, ierr := generateHashCount(c)
		if ierr != nil {
			err = ierr
			return
		}
		hash, ierr := hmacMsg(msg, key, h)
		if ierr != nil {
			err = ierr
			return
		}
		otpInt := int(math.Mod(float64(extractFromHash(hash)), math.Pow(10, float64(digits))))
		otp := fmt.Sprintf("%0"+strconv.Itoa(digits)+"d", otpInt)
		otps = append(otps, otp)
	}
	return
}

// Generate a base32 encoded secret string to be shared between the client and the server for OTPs
// Specify the length of the secret to generate in bytes. Note this needs to be at least 16 bytes / 128 bits.
func GenerateOTPSecret(s int) (string, error) {
	if s < 16 {
		return "", errors.New("The secret size needs to be at least 16 bytes / 128 bits")
	}
	b, err := generateRandomBytes(s)
	return base32.StdEncoding.EncodeToString(b), err
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
