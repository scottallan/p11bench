package main

import (
	"flag"
	"fmt"
	//"github.com/gbolo/go-util/lib/debugging"
	"crypto/sha256"
	"encoding/asn1"
	"os"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

var (
	module          = "/usr/lib/softhsm/libsofthsm2.so"
	tokenLabel      = "ForFabric"
	privateKeyLabel = "fd6eaeb99b2eea3f51c30acc83242ac9430d800183abf90a1f47c754cf9fc0f8"
	pin             = "98765432"
	sessionCacheSize = 10
)
# Look at https://github.com/hyperledger/fabric/blob/release-1.1/bccsp/pkcs11/impl.go

func init() {
	if x := os.Getenv("SOFTHSM_LIB"); x != "" {
		module = x
	}
	if x := os.Getenv("SOFTHSM_TOKENLABEL"); x != "" {
		tokenLabel = x
	}
	if x := os.Getenv("SOFTHSM_PRIVKEYLABEL"); x != "" {
		privateKeyLabel = x
	}
	if x := os.Getenv("SOFTHSM_PIN"); x != "" {
		pin = x
	}
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")
}

func exitWhenError(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func main() {

	action := flag.String("action", "runAll", "runAll, runInSingleSession, RunInUniqueSession")
	runs   := flag.Int("runs",1000,"Interations for Testing, Default 1000")
	flag.Parse()

	switch *action {
	case "runInSingleSession":
		signInSameSession(*runs)

	case "RunInUniqueSession":
		signInUniqueSession(*runs)

	default:
		signInSameSession(*runs)
		signInUniqueSession(*runs)
	}

}

func getP11Attributes() (pub, priv []*pkcs11.Attribute) {

	ecParam, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})

	pub = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), /* session only. destroy later */
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParam),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("gbolotest")),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "gbolotest"),
		// public key should be easily accessed
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	}

	priv = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), /* session only. destroy later */
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("gbolotest")),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "gbolotest"),
		// TODO: make these options configurable...
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		// support key derivation by default for now...
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		// pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, false),
	}

	return
}

func getP11KeyAttributes() (priv []*pkcs11.Attribute) {
	priv = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, privateKeyLabel),
	}

	return
}

func getMessageDigest() (digest []byte) {
	message := "some test message"
	d := sha256.Sum256([]byte(message))
	digest = d[:]

	return
}

func signInSameSession(numOfSigns int) {

	fmt.Println("Starting signInSameSession")

	module, err := p11.OpenModule(module)
	exitWhenError(err)

	//info, err := module.Info()
	//exitWhenError(err)
	//debugging.PrettyPrint(info)

	slots, err := module.Slots()
	exitWhenError(err)

	mySlot := p11.Slot{}
	for _, slot := range slots {

		//sinfo, err := slot.Info()
		//exitWhenError(err)
		//debugging.PrettyPrint(sinfo)

		tinfo, err := slot.TokenInfo()
		exitWhenError(err)
		//debugging.PrettyPrint(tinfo)

		if tinfo.Label == tokenLabel {
			mySlot = slot
		}

	}

	session, err := mySlot.OpenWriteSession()
	exitWhenError(err)

	err = session.Login(pin)
	exitWhenError(err)

	// generate keypair
	p11PubAttr, p11PrivAttr := getP11Attributes()
	keypair, err := session.GenerateKeyPair(p11.GenerateKeyPairRequest{
		Mechanism:            *pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
		PublicKeyAttributes:  p11PubAttr,
		PrivateKeyAttributes: p11PrivAttr,
	})
	exitWhenError(err)

	// do signs
	digest := getMessageDigest()
	start := time.Now()
	for i := 0; i < numOfSigns; i++ {
		_, err := keypair.Private.Sign(*pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), []byte(digest))
		exitWhenError(err)
		//fmt.Printf("%x\n", sig)
	}
	elapsed := time.Since(start)
	fmt.Printf("Signing took %s\n", elapsed)
	fmt.Println("DONE")

	//err = session.Logout()
	//exitWhenError(err)
	err = session.Close()
	exitWhenError(err)

}

func signInUniqueSession(numOfSigns int) {

	fmt.Println("Starting signInUniqueSession")

	module, err := p11.OpenModule(module)
	exitWhenError(err)

	//info, err := module.Info()
	//exitWhenError(err)
	//debugging.PrettyPrint(info)

	slots, err := module.Slots()
	exitWhenError(err)

	mySlot := p11.Slot{}
	for _, slot := range slots {

		//sinfo, err := slot.Info()
		//exitWhenError(err)
		//debugging.PrettyPrint(sinfo)

		tinfo, err := slot.TokenInfo()
		exitWhenError(err)
		//debugging.PrettyPrint(tinfo)

		if tinfo.Label == tokenLabel {
			mySlot = slot
		}

	}

	digest := getMessageDigest()
	start := time.Now()
	for i := 0; i < numOfSigns; i++ {

		session, err := mySlot.OpenWriteSession()
		exitWhenError(err)

		err = session.Login(pin)
		exitWhenError(err)

		// get private key
		p11PrivAttr := getP11KeyAttributes()
		obj, err := session.FindObject(p11PrivAttr)
		exitWhenError(err)

		key := p11.PrivateKey(obj)

		// do signs
		_, err = key.Sign(*pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), []byte(digest))
		exitWhenError(err)
		//fmt.Printf("%x\n", sig)
		err = session.Close()
		exitWhenError(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("Signing took %s\n", elapsed)
	fmt.Println("DONE")

	//err = session.Logout()
	//exitWhenError(err)

}
