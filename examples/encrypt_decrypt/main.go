package main

import (
	"fmt"
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
	data := "abc 123 张大鹏"
	fmt.Println(data)

	// 加密
	encrypt, err := r.Encrypt([]byte(data))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(encrypt))

	// 解密
	decrypt, err := r.Decrypt(encrypt)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decrypt))
}
