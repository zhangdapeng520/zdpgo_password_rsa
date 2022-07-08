package zdpgo_password_rsa

// Config RSA加密核心配置
type Config struct {
	PrivateKeyPath string `yaml:"private_key_path" json:"private_key_path"` // 私钥文件路径
	PublicKeyPath  string `yaml:"public_key_path" json:"public_key_path"`   // 公钥文件路径
	BitSize        int    `yaml:"bit_size" json:"bit_size"`                 // 私钥文件的key长度
}
