package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Message struct {
	Title   string    `json:"title"`
	Content string    `json:"content"`
	Time    time.Time `json:"time"`
}

var (
	messages []Message
	mu       sync.Mutex
)

func uploadFile(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到上传文件"})
		return
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	isImage := ext == ".jpg" || ext == ".png" || ext == ".jpeg" || ext == ".webp" || ext == ".gif"

	saveDir := "./static/files"
	if isImage {
		saveDir = "./static/images"
	}
	_ = os.MkdirAll(saveDir, os.ModePerm)

	// 使用原始文件名，但防止穿越
	safeName := filepath.Base(file.Filename)
	savePath := filepath.Join(saveDir, safeName)

	if err := c.SaveUploadedFile(file, savePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
		return
	}

	urlPath := "/static/files/" + safeName
	if isImage {
		urlPath = "/static/images/" + safeName
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "上传成功",
		"url":     urlPath,
		"type":    isImage,
	})
}

func listFiles(c *gin.Context) {
	fileType := c.DefaultQuery("type", "image") // image or file
	dir := "./static/images"
	prefix := "/static/images/"
	if fileType == "file" {
		dir = "./static/files"
		prefix = "/static/files/"
	}

	_ = os.MkdirAll(dir, os.ModePerm)
	entries, err := os.ReadDir(dir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取失败"})
		return
	}

	var list []gin.H
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		list = append(list, gin.H{
			"name": e.Name(),
			"url":  prefix + e.Name(),
			"size": info.Size(),
			"time": info.ModTime(),
		})
	}

	c.JSON(http.StatusOK, gin.H{"list": list})
}

func deleteItems(c *gin.Context) {
	var req struct {
		Type  string   `json:"type"` // image or file
		Names []string `json:"names"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}

	baseDir := "./static/images"
	if req.Type == "file" {
		baseDir = "./static/files"
	}

	var deleted []string
	failed := make(map[string]string)

	for _, name := range req.Names {
		if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
			failed[name] = "非法文件名"
			continue
		}
		path := filepath.Join(baseDir, name)
		if err := os.Remove(path); err != nil {
			failed[name] = err.Error()
		} else {
			deleted = append(deleted, name)
		}
	}

	c.JSON(http.StatusOK, gin.H{"deleted": deleted, "failed": failed})
}

func notifyHandler(c *gin.Context) {
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 你现有的通知逻辑
	if req.Content != "" {
		if err := sendWindowsNotification(req.Title, req.Content); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// 也把消息加入消息列表（带时间）
	msg := Message{
		Title:   req.Title,
		Content: req.Content,
		Time:    time.Now(),
	}
	mu.Lock()
	messages = append(messages, msg)
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"success": true, "msg": "received"})
}

func sendWindowsNotification(title, message string) error {
	ps := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
$xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("%s")) > $null
$xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("%s")) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("%s")
$notifier.Show($toast)
`, message, title, title)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", ps)
	return cmd.Run()
}

func main() {
	// 创建一个默认的gin引擎
	r := gin.Default()

	// 静态文件服务
	r.StaticFile("/favicon.ico", "./static/favicon.ico")

	// 图片/文件上传接口
	r.POST("/upload", uploadFile)

	// 访问根路径时返回 index.html 页面
	r.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	// 访问 store 可以查看所有图片
	r.GET("/store", func(c *gin.Context) {
		c.File("./static/store.html")
	})

	r.GET("/api/list", listFiles)

	r.GET("/messages", func(c *gin.Context) {
		mu.Lock()
		defer mu.Unlock()
		c.JSON(http.StatusOK, gin.H{
			"messages": messages,
		})
	})

	r.POST("/notify", notifyHandler)

	r.POST("/message", func(c *gin.Context) {
		var req struct {
			Title   string `json:"title"`
			Content string `json:"content"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if req.Title == "" || req.Content == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "标题和内容不能为空"})
			return
		}

		message := Message{
			Title:   req.Title,
			Content: req.Content,
			Time:    time.Now(),
		}
		mu.Lock()
		messages = append(messages, message)
		mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": message,
		})
	})

	r.DELETE("/api/items", deleteItems)

	r.DELETE("/message/:index", func(c *gin.Context) {
		indexStr := c.Param("index")
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
			return
		}

		mu.Lock()
		defer mu.Unlock()
		if index < 0 || index >= len(messages) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "index out of range"})
			return
		}

		messages = append(messages[:index], messages[index+1:]...)

		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// 暴露静态文件访问
	r.Static("/static/images", "./static/images")
	r.Static("/static/files", "./static/files")

	// 启动服务器，监听192.168.253.74:8080端口
	err := r.Run(":8080")
	// 如果启动失败，打印错误信息
	if err != nil {
		fmt.Println("启动失败：" + err.Error())
		return
	}
}
