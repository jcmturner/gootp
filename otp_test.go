package gootp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"hash"
	"testing"
	"time"
)

func TestHOTP(t *testing.T) {
	secret := "12345678901234567890"
	secret32encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	sha1Func := sha1.New
	var tests = []struct {
		count   int64
		mode    func() hash.Hash
		digits  int
		optWant string
	}{
		{0, nil, 6, "755224"},
		{1, nil, 6, "287082"},
		{2, nil, 6, "359152"},
		{3, nil, 6, "969429"},
		{4, nil, 6, "338314"},
		{5, nil, 6, "254676"},
		{6, nil, 6, "287922"},
		{7, nil, 6, "162583"},
		{8, nil, 6, "399871"},
		{9, nil, 6, "520489"},
		{0, sha1Func, 6, "755224"},
		{1, sha1Func, 6, "287082"},
		{2, sha1Func, 6, "359152"},
		{3, sha1Func, 6, "969429"},
		{4, sha1Func, 6, "338314"},
		{5, sha1Func, 6, "254676"},
		{6, sha1Func, 6, "287922"},
		{7, sha1Func, 6, "162583"},
		{8, sha1Func, 6, "399871"},
		{9, sha1Func, 6, "520489"},
	}
	for _, test := range tests {
		if otpGot, _ := HOTP(secret32encoded, test.count, test.mode, test.digits); otpGot != test.optWant {
			t.Errorf("totp.HOTP(%q, %v, hash, %v) = %v, want one time password %v\n", secret32encoded, test.count, test.digits, otpGot, test.optWant)
		}
	}
}

func TestTOTP(t *testing.T) {
	// Test secrets should be noted from RFC 6238 errata 2866 https://www.rfc-editor.org/errata_search.php?rfc=6238
	secret32encodedSHA1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secret32encodedSHA256 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secret32encodedSHA512 := base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
	sha1Func := sha1.New
	sha256Func := sha256.New
	sha512Func := sha512.New
	var tests = []struct {
		time       int64
		mode       func() hash.Hash
		digits     int
		optWant    string
		remainWant int
	}{
		{59, sha1Func, 8, "94287082", 1},
		{59, sha256Func, 8, "46119246", 1},
		{59, sha512Func, 8, "90693936", 1},
		{1111111109, sha1Func, 8, "07081804", 1},
		{1111111109, sha256Func, 8, "68084774", 1},
		{1111111109, sha512Func, 8, "25091201", 1},
		{1111111111, sha1Func, 8, "14050471", 29},
		{1111111111, sha256Func, 8, "67062674", 29},
		{1111111111, sha512Func, 8, "99943326", 29},
		{1234567890, sha1Func, 8, "89005924", 30},
		{1234567890, sha256Func, 8, "91819424", 30},
		{1234567890, sha512Func, 8, "93441116", 30},
		{2000000000, sha1Func, 8, "69279037", 10},
		{2000000000, sha256Func, 8, "90698825", 10},
		{2000000000, sha512Func, 8, "38618901", 10},
		{20000000000, sha1Func, 8, "65353130", 10},
		{20000000000, sha256Func, 8, "77737706", 10},
		{20000000000, sha512Func, 8, "47863826", 10},
	}
	for _, test := range tests {
		var secret string
		switch test.mode().Size() {
		case 20:
			secret = secret32encodedSHA1
		case 32:
			secret = secret32encodedSHA256
		case 64:
			secret = secret32encodedSHA512
		default:
			secret = secret32encodedSHA1
		}
		if optGot, remainGot, _ := TOTPAt(secret, time.Unix(test.time, 0).UTC(), test.mode, test.digits); optGot != test.optWant {
			t.Errorf("totp.TOTPAt(%q, time.Unix(%v, 0).UTC()) = %v, want one time password %v", secret, test.time, optGot, test.optWant)
		} else if remainGot != test.remainWant {
			t.Errorf("totp.TOTPAt(%q, time.Unix(%v, 0).UTC()) = %v, want time remaining %v", secret, test.time, remainGot, test.remainWant)
		}
	}
}

func TestTOTPNow(t *testing.T) {
	secret := "12345678901234567890"
	secret32encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	if otpGot, _, _ := TOTPNow(secret32encoded, sha1.New, 6); len(otpGot) != 6 {
		t.Errorf("GetTOTPNow(%q, sha1.New, 6) = %v, want length of 6", secret32encoded, otpGot)
	}

}

func TestGetTOTPHistory(t *testing.T) {
	secret := "12345678901234567890"
	secret32encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	if otpsGot, _, _ := TOTPHistory(secret32encoded, sha1.New, 6, 3); len(otpsGot) != 3 {
		t.Errorf("GetTOTPHistory(%q, sha1.New, 6, 3) = %v, wanted array of 3 OTPs", secret32encoded, otpsGot)
	} else {
		latestOtp, _, _ := TOTPNow(secret32encoded, sha1.New, 6)
		if otpsGot[0] != latestOtp {
			t.Error("First element in OTP history array is not the latest OTP")
		}
	}
}

func TestGenerateOTPSecret(t *testing.T) {
	if secret, _ := GenerateOTPSecret(20); len(secret) != 32 {
		t.Errorf("GenerateOTPSecret(20) = %v, length %v, want length 32", secret, len(secret))
	}
}
