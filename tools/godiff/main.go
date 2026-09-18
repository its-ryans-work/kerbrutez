// Differential reference generator: prints the bytes gokrb5 produces for a set
// of fixed inputs, so the Zig krb5 implementation can be checked byte-for-byte.
//
// Usage: go run . <what>
//   asreq   - AS-REQ (no pre-auth) and AS-REQ (with a fixed PA-ENC-TIMESTAMP)
//   encdata - EncryptedData with KVNO=0 (omitted) and KVNO=5
//   decrypt <etype> <keyhex> <cipherhex> <usage> - decrypt and print plaintext
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ropnop/gokrb5/v8/crypto"
	"github.com/ropnop/gokrb5/v8/iana/flags"
	"github.com/ropnop/gokrb5/v8/messages"
	"github.com/ropnop/gokrb5/v8/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run . asreq|encdata|decrypt ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "asreq":
		asreq()
	case "encdata":
		encdata()
	case "decrypt":
		decrypt()
	default:
		fmt.Println("unknown:", os.Args[1])
		os.Exit(2)
	}
}

func asreq() {
	opts := types.NewKrbFlags()
	types.SetFlag(&opts, flags.RenewableOK)
	till := time.Unix(1704164645, 0).UTC()
	a := messages.ASReq{KDCReqFields: messages.KDCReqFields{
		PVNO: 5, MsgType: 10, PAData: types.PADataSequence{},
		ReqBody: messages.KDCReqBody{
			KDCOptions: opts, Realm: "EXAMPLE.COM",
			CName: types.PrincipalName{NameType: 1, NameString: []string{"user"}},
			SName: types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "EXAMPLE.COM"}},
			Till: till, Nonce: 305419896, EType: []int32{18, 17, 16, 23},
		},
	}}
	b, _ := a.Marshal()
	fmt.Println("ASREQ_NOPA", hex.EncodeToString(b))
	a.PAData = types.PADataSequence{types.PAData{PADataType: 2, PADataValue: []byte{0xDE, 0xAD, 0xBE, 0xEF}}}
	b2, _ := a.Marshal()
	fmt.Println("ASREQ_PA", hex.EncodeToString(b2))
}

func encdata() {
	ed := types.EncryptedData{EType: 18, KVNO: 0, Cipher: []byte{0xAA, 0xBB}}
	b, _ := ed.Marshal()
	fmt.Println("KVNO0", hex.EncodeToString(b))
	ed2 := types.EncryptedData{EType: 18, KVNO: 5, Cipher: []byte{0xAA, 0xBB}}
	b2, _ := ed2.Marshal()
	fmt.Println("KVNO5", hex.EncodeToString(b2))
}

func decrypt() {
	etype, _ := strconv.Atoi(os.Args[2])
	key, _ := hex.DecodeString(os.Args[3])
	ct, _ := hex.DecodeString(os.Args[4])
	usage, _ := strconv.Atoi(os.Args[5])
	k := types.EncryptionKey{KeyType: int32(etype), KeyValue: key}
	pt, err := crypto.DecryptMessage(ct, k, uint32(usage))
	fmt.Printf("%q err=%v\n", string(pt), err)
}
