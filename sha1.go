package zdpgo_password_rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
)

// EncryptSha1 基于SHA1加密算法的RAS加密
func (r *Rsa) EncryptSha1(data []byte) ([]byte, error) {
	// 获取公钥
	publicKeyByte, err := ioutil.ReadFile(r.Config.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	// 获取块
	block, _ := pem.Decode(publicKeyByte)

	// 解析公钥
	parseResultPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// 转换公钥
	publicKey := parseResultPublicKey.(*rsa.PublicKey)

	// 执行加密
	encryptedBytes, err := rsa.EncryptOAEP(
		sha1.New(),
		rand.Reader,
		publicKey,
		data,
		nil)
	if err != nil {
		return nil, err
	}

	// 返回加密数据
	return encryptedBytes, nil
}

// EncryptSha1String 此算法的加密结果能够被zdppy-python的RSA的decrypt方法解密
func (r *Rsa) EncryptSha1String(data string) (string, error) {
	// 获取加密的字节数组
	encrypt, err := r.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}

	// 将加密结果转换为base64编码的字符串然后返回
	return base64.StdEncoding.EncodeToString(encrypt), nil
}

// DecryptSha1 Sha1方式的RSA解密
func (r *Rsa) DecryptSha1(data []byte) ([]byte, error) {
	// 获取私钥
	privateKeyByte, err := ioutil.ReadFile(r.Config.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	// 获取块
	block, _ := pem.Decode(privateKeyByte)

	// 解析私钥
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	// 解密
	decryptedBytes, err := privateKey.Decrypt(rand.Reader, data, &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, err
	}

	// 返回解密数据
	return decryptedBytes, nil
}

// DecryptSha1String Sha1方式的RSA解密
func (r *Rsa) DecryptSha1String(data string) (string, error) {
	// 解析base64的字符串
	b64Data, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	// 获取解密字节数组
	decrypt, err := r.Decrypt(b64Data)
	if err != nil {
		return "", err
	}

	// 返回解密字符串
	return string(decrypt), nil
}
