package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

var key = flag.String("key", "ZL7GN6U2BGNFWYLCKFTALTS2A6CTCWGK", "secret key")

func main() {
	flag.Parse()
	c, err := getCode(*key, time.Now().Unix()/30)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(c)
}

// GetCode Calculate the code, with given secret and point in time
func getCode(secret string, t int64) (string, error) {
	secret = strings.ToUpper(secret)
	secretKey, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	tim, err := hex.DecodeString(fmt.Sprintf("%016x", t))
	if err != nil {
		return "", err
	}
	hm := HmacSHA1(secretKey, tim)
	offset := hm[len(hm)-1] & 0x0F
	hashPart := hm[offset : offset+4]
	value, err := strconv.ParseInt(hex.EncodeToString(hashPart), 16, 0)
	if err != nil {
		return "", err
	}
	value = value & 0x7FFFFFFF
	mod := int64(math.Pow(10, 6))
	format := fmt.Sprintf("%%0%dd", 6)
	return fmt.Sprintf(format, value%mod), nil
}

func HmacSHA1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
