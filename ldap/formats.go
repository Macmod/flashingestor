package ldap

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func EndianConvert(sd string) (newSD string) {
	sdBytes, _ := hex.DecodeString(sd)

	for i, j := 0, len(sdBytes)-1; i < j; i, j = i+1, j-1 {
		sdBytes[i], sdBytes[j] = sdBytes[j], sdBytes[i]
	}

	newSD = hex.EncodeToString(sdBytes)

	return
}

func HexToDecimalString(hex string) (decimal string) {
	integer, _ := strconv.ParseInt(hex, 16, 64)
	decimal = strconv.Itoa(int(integer))

	return
}

func ConvertSID(hexSID string) (SID string) {
	if len(hexSID) < 16 {
		return ""
	}

	var fields []string
	fields = append(fields, hexSID[0:2])
	if len(fields) > 0 && fields[0] == "01" {
		fields[0] = "S-1"
	}
	numDashes, _ := strconv.Atoi(HexToDecimalString(hexSID[2:4]))

	fields = append(fields, "-"+HexToDecimalString(hexSID[4:16]))

	lower, upper := 16, 24
	for i := 1; i <= numDashes; i++ {
		if upper > len(hexSID) {
			break
		}
		fields = append(fields, "-"+HexToDecimalString(EndianConvert(hexSID[lower:upper])))
		lower += 8
		upper += 8
	}

	for i := 0; i < len(fields); i++ {
		SID += (fields[i])
	}

	return
}

func BytesToGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}

	hexStr := hex.EncodeToString(b)
	return ConvertGUID(hexStr)
}

func ConvertGUID(portion string) string {
	if len(portion) < 32 {
		return ""
	}

	portion1 := EndianConvert(portion[0:8])
	portion2 := EndianConvert(portion[8:12])
	portion3 := EndianConvert(portion[12:16])
	portion4 := portion[16:20]
	portion5 := portion[20:]
	return portion1 + "-" + portion2 + "-" + portion3 + "-" + portion4 + "-" + portion5
}

func EncodeGUID(guid string) (string, error) {
	tokens := strings.Split(guid, "-")
	if len(tokens) != 5 {
		return "", fmt.Errorf("Wrong GUID format")
	}

	result := ""
	result += EndianConvert(tokens[0])
	result += EndianConvert(tokens[1])
	result += EndianConvert(tokens[2])
	result += tokens[3]
	result += tokens[4]
	return result, nil
}
