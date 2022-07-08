package zdpgo_password_rsa

import "testing"

func getRsa() *Rsa {
	return New()
}

func TestRsa_GenerateKey(t *testing.T) {
	r := getRsa()
	r.GenerateKey()
}

func TestRsa_Decrypt(t *testing.T) {
	r := getRsa()
	data := "abc 123 张大鹏"

	// 加密
	encrypt, err := r.Encrypt([]byte(data))
	if err != nil {
		t.Error(err)
	}

	// 解密
	_, err = r.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
	}
}

func TestRsa_DecryptString(t *testing.T) {
	r := getRsa()
	data := "abc 123 张大鹏"

	// 加密
	encrypt, err := r.EncryptString(data)
	if err != nil {
		t.Error(err)
	}

	// 解密
	_, err = r.DecryptString(encrypt)
	if err != nil {
		t.Error(err)
	}
}
