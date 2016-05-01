package gootp

import (
	"crypto/sha1"
	"encoding/base32"
	"hash"
	"testing"
	"time"
)

func TestHOTP(t *testing.T) {
	secret := "12345678901234567890"
	secret32encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	var tests = []struct {
		count   int64
		mode    func() hash.Hash
		digits  int
		optWant string
	}{
		{0, sha1.New, 6, "755224"},
		{1, sha1.New, 6, "287082"},
		{2, sha1.New, 6, "359152"},
		{3, sha1.New, 6, "969429"},
		{4, sha1.New, 6, "338314"},
		{5, sha1.New, 6, "254676"},
		{6, sha1.New, 6, "287922"},
		{7, sha1.New, 6, "162583"},
		{8, sha1.New, 6, "399871"},
		{9, sha1.New, 6, "520489"},
	}
	for _, test := range tests {
		if otpGot, _ := GetHOTP(secret32encoded, test.count, test.mode, test.digits); otpGot != test.optWant {
			t.Errorf("totp.GetHOTP(%q, %v, %q, %v) = %v, want one time password %v", secret32encoded, test.count, test.mode, test.digits, otpGot, test.optWant)
		}
	}
}

func TestTOTP(t *testing.T) {
	secret := "12345678901234567890"
	secret32encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	//	timestep := 30
	var tests = []struct {
		time       int64
		mode       func() hash.Hash
		digits     int
		optWant    string
		remainWant int
	}{
		{59, sha1.New, 8, "94287082", 1},
		{1111111109, sha1.New, 8, "07081804", 1},
		{1111111111, sha1.New, 8, "14050471", 29},
		{1234567890, sha1.New, 8, "89005924", 30},
		{2000000000, sha1.New, 8, "69279037", 10},
		{20000000000, sha1.New, 8, "65353130", 10},
	}
	for _, test := range tests {
		if optGot, remainGot, _ := GetTOTPAt(secret32encoded, time.Unix(test.time, 0).UTC(), test.mode, test.digits); optGot != test.optWant {
			t.Errorf("totp.GetAt(%q, time.Unix(%v, 0).UTC()) = %v, want one time password %v", secret32encoded, test.time, optGot, test.optWant)
		} else if remainGot != test.remainWant {
			t.Errorf("totp.GetAt(%q, time.Unix(%v, 0).UTC()) = %v, want time remaining %v", secret32encoded, test.time, remainGot, test.remainWant)
		} else {
			t.Logf("Testing %v seconds after epoch = %v. TOTP result: %v Time remaining: %v", test.time, time.Unix(test.time, 0).UTC(), optGot, remainGot)
		}
	}
}
