package auth

//Auth 接口应实现一个Auth函数，传入token，返回username
type Auth interface {
	Auth(token string) (user string, err error)
}

//New 创建一个Auth实例
func New() (a Auth, err error) {
	return NewConfigAuth(secretPath)
}

//secretPath 密码文件存储路径
var secretPath = "/etc/ngrok-secrets"

//SetSecretPath 重新设置一个密码文件存储位置
func SetSecretPath(path string) {
	secretPath = path
}
