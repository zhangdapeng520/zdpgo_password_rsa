package main

import (
	"github.com/zhangdapeng520/zdpgo_password_rsa"
)

/*
@Time : 2022/7/8 14:11
@Author : 张大鹏
@File : main.go
@Software: Goland2021.3.1
@Description: RSA加密和解密
*/

func main() {
	r := zdpgo_password_rsa.New()

	// 生成私钥
	privateKey := r.GeneratePrivateKey()

	// 生成公钥
	r.GeneratePublicKey(privateKey)

	// 同时生成公钥和私钥
	r.GenerateKey()
}
