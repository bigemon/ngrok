package auth

import (
	"bufio"
	"errors"
	"fmt"
	"ngrok/log"
	"os"
	"strings"
	"sync"
	"time"
)

//ConfigAuth Auth实现,使用配置文件作为密码载体
type ConfigAuth struct {
	path        string
	tokens      map[string]string
	lastModTime int64
	lock        *sync.RWMutex
	stopGor     bool
}

//NewConfigAuth 创建一个新的ConfigAuth实例
func NewConfigAuth(path string) (c *ConfigAuth, err error) {
	c = &ConfigAuth{
		path:   path,
		tokens: make(map[string]string),
		lock:   &sync.RWMutex{},
	}
	if err = c.autoReload(); err != nil {
		return
	}
	go func() {
		for !c.stopGor {
			time.Sleep(time.Second * 10)
			err = c.autoReload()
			if err != nil {
				log.Warn("reload %v failed with error %v", path, err)
			}
		}
	}()
	return c, nil
}

func (p *ConfigAuth) autoReload() error {
	//判断文件最后修改时间
	fi, err := os.Stat(p.path)
	if err != nil {
		err = fmt.Errorf("Failed to read configuration file %s: %v", p.path, err)
		return err
	}
	p.lock.RLock()
	lmt := p.lastModTime
	p.lock.RUnlock()
	if fi.ModTime().Unix() == lmt { //修改时间没变过,就不要重载了
		return nil
	}
	//开始重载密码配置
	file, err := os.Open(p.path)
	if err != nil {
		err = fmt.Errorf("Failed to read configuration file %s: %v", p.path, err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	newTokens := make(map[string]string)
	for scanner.Scan() {
		text := scanner.Text()
		toParse := strings.Split(text, "#")[0] //去掉#备注的内容
		fields := strings.Fields(toParse)
		if len(fields) != 2 {
			continue
		}
		newTokens[fields[0]] = fields[1]
		if len(fields[1]) >= 32 { //如果是32位数的token
			newTokens[fields[1]] = fields[0]
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	//重载结果塞回结构
	p.lock.Lock()
	p.tokens = newTokens
	p.lastModTime = fi.ModTime().Unix()
	p.lock.Unlock()
	log.Info("config %v reload complete", p.path)
	return nil
}

//Auth 校验一个token是否有效
func (p *ConfigAuth) Auth(token string) (userName string, err error) {
	fields := strings.Split(token, ":")
	fLen := len(fields)
	if fLen > 2 {
		err = errors.New("wrong format of token")
		return
	}
	if fLen == 1 { //只提供了token
		if len(token) < 32 {
			return "", errors.New("wrong format of token")
		}
		p.lock.RLock()
		userName, ok := p.tokens[token]
		p.lock.RUnlock()
		if ok {
			return userName, nil
		}
		return "", errors.New("invaild token")
	}
	username := fields[0]
	password := fields[1]

	p.lock.RLock()
	if p.tokens[username] == password {
		p.lock.RUnlock()
		return username, nil
	}
	p.lock.RUnlock()
	return "", errors.New("invaild token")
}

//Close 关闭并释放资源
func (p *ConfigAuth) Close() {
	p.stopGor = false
}
