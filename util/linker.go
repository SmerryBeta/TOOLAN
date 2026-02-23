package util

import (
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type DataBase interface {
	GetDB() *gorm.DB // 获取数据库连接
	Close()          // 数据库接口
}

type Mysql struct {
	db       *gorm.DB
	username string
	password string
	database string
	host     string
	port     string
}

// GetDB 获取数据库连接
func (m *Mysql) GetDB() *gorm.DB {
	return m.db
}

// Close 关闭数据库连接
func (m *Mysql) Close() {

}

func NewMysqlFromConfig() *Mysql {
	return NewMysqlDataBaseFromPath("config.yml")
}

func NewMysqlDataBaseFromPath(path string) *Mysql {
	loader := LoadYamlFromPath(path)

	UserName := loader.GetString("UserName")
	Password := loader.GetString("Password")
	Database := loader.GetString("Database")

	Host := loader.GetStringOrElse("127.0.0.1", "Host")
	Port := loader.GetStringOrElse("3306", "Port")

	// 构件数据库连接字符串
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		UserName,
		Password,
		Host,
		Port,
		Database,
	)

	m := &Mysql{
		username: UserName,
		password: Password,
		host:     Host,
		database: Database,
		port:     Port,
	}

	m.initDB(dsn)
	return m
}

// 初始化数据库连接
func (m *Mysql) initDB(dsn string) {
	// 数据库连接字符串
	var err error
	// 使用gorm库连接数据库
	m.db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	// 如果连接失败，则抛出异常
	if err != nil {
		panic("数据库连接失败：" + err.Error())
	}
}
