package main

import (
	"BackEnd/reviewer"
	"BackEnd/util"
	"bytes"
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
	"io"
	"log"
	"net/http"
	"time"
)

// Model 基类
type Model struct {
	Id        uint           `gorm:"primarykey" yaml:"id" json:"id"`
	CreatedAt time.Time      `yaml:"createdAt" json:"createdAt"`
	UpdatedAt time.Time      `yaml:"UpdatedAt" json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" yaml:"deletedAt" json:"deletedAt"`
}

// Good 基类
type Good struct {
	Model     `json:",inline" yaml:",inline"`
	Name      string `json:"name" yaml:"name"`
	ImagePath string `json:"image" yaml:"image"`
	Level     string `json:"level" yaml:"level"`
	//LotteryGoods []LotteryGood `gorm:"foreignKey:GoodId" json:"lotteryGoods" yaml:"lotteryGoods"`
}

// LotteryGood 抽奖机里的物品
type LotteryGood struct {
	Model `json:",inline" yaml:",inline"`
	// 外键字段：指向 Good 表的 ID
	GoodID uint `json:"goodId" yaml:"goodId" gorm:"not null"`
	// GORM 关联字段：用于加载关联的 Good 数据，不会存储在数据库中
	Good     Good    `json:"good" yaml:"good" gorm:"foreignKey:GoodID"`
	Count    int     `json:"count" yaml:"count"`
	MaxCount int     `json:"maxCount" yaml:"maxCount"`
	Price    int64   `json:"price" yaml:"price"`
	Rate     float64 `json:"mall" yaml:"mall"`
}

// PlayerItem 代表玩家背包中的一个物品记录
type PlayerItem struct {
	Model    `json:",inline" yaml:",inline"`
	PlayerID uint `json:"playerId" gorm:"not null;index"`            // 玩家的 Id
	RecordId uint `json:"recordId" yaml:"recordId" gorm:"index"`     // 指向 LotteryRecord.ID
	GoodID   uint `json:"goodId" gorm:"not null"`                    // 物品的 Id
	Good     Good `json:"good" yaml:"good" gorm:"foreignKey:GoodID"` // 物品基类
	Count    int  `json:"count" gorm:"not null"`                     // 物品的数量
}

type Player struct {
	Model        `json:",inline" yaml:",inline"`
	Salt         string       `json:"-"`
	Password     string       `json:"-"`
	Username     string       `json:"username"`
	Gender       string       `json:"gender"` // male or female or undefined
	Avatar       string       `json:"avatar"`
	Balance      int64        `json:"balance"`
	MarketMarker bool         `json:"banker"`
	Role         string       `json:"role"` // user or admin or trader
	Inventory    []PlayerItem `json:"inventory" gorm:"foreignKey:PlayerID"`
}

func mergeInventory(items []PlayerItem) []PlayerItem {
	resultMap := make(map[uint]PlayerItem, len(items))

	for _, item := range items {
		if item.Count == 0 {
			continue
		}

		id := item.Good.Id
		if existing, ok := resultMap[id]; ok {
			existing.Count += item.Count
			resultMap[id] = existing
		} else {
			resultMap[id] = item
		}
	}

	result := make([]PlayerItem, 0, len(resultMap))
	for _, item := range resultMap {
		result = append(result, item)
	}
	return result
}

func (p *Player) SaveInventoryToDB(db *gorm.DB) error {
	// 合并数量
	p.Inventory = mergeInventory(p.Inventory)
	// 保存事务
	return db.Transaction(func(tx *gorm.DB) error {
		var dbItems []PlayerItem
		if err := tx.
			Where("player_id = ?", p.Id).
			Find(&dbItems).Error; err != nil {
			return err
		}

		// 1. 建立映射
		dbMap := make(map[uint]PlayerItem)
		for _, item := range dbItems {
			dbMap[item.Id] = item
		}

		memMap := make(map[uint]PlayerItem)
		for _, item := range p.Inventory {
			memMap[item.Id] = item
		}

		// 2. 更新 & 新增
		for _, item := range p.Inventory {
			item.PlayerID = p.Id

			if item.Id == 0 {
				// 新物品
				if err := tx.Create(&item).Error; err != nil {
					return err
				}
			} else {
				// 更新已有
				if err := tx.Model(&item).Updates(map[string]interface{}{
					"count": item.Count,
				}).Error; err != nil {
					return err
				}
			}
		}

		// 3. 删除内存中不存在的
		for id := range dbMap {
			if _, ok := memMap[id]; !ok {
				if err := tx.Delete(&PlayerItem{}, id).Error; err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func main() {
	// 构建客户端
	cli := reviewer.NewClient("http://127.0.0.1:9000")

	// 文本审核
	txtResp, err := cli.ReviewText("FUCK YOU")
	if err != nil {
		log.Fatal("文本审核失败:", err)
	}
	fmt.Printf("文本审核结果: %+v\n", txtResp)

	// 图片审核
	imgResp, err := cli.ReviewImage("./static/images/20260104084358.jpg")
	if err != nil {
		log.Fatal("图片审核失败:", err)
	}
	fmt.Printf("图片审核结果: %+v\n", imgResp)
	//DbOperate()
	//pushDataIntoDataBaseTest()
}

func DbOperate() {
	base := util.NewMysqlFromConfig()
	db := base.GetDB()

	// 自动迁移数据库表结构
	err := db.AutoMigrate(&Player{}, &PlayerItem{}, &Good{})
	if err != nil {
		fmt.Println("数据库迁移失败:", err)
		return
	}

	// TODO 添加物品
	//Good := Good{Name: "diamond_axe", ImagePath: "diamond_axe.png", Level: "epic"}
	//db.Create(&Good)

	//pixel := &PlayerItem{Good: Good}

	//addedPlayer := &Player{Username: "Fortysoilder", Role: "user"}
	//addedPlayer.Inventory = append(addedPlayer.Inventory, *pixel)
	//db.Create(&addedPlayer)
	//
	//pixel.PlayerID = addedPlayer.Id
	//db.Create(&pixel)

	//// TODO 添加玩家
	////addedPlayer := &Player{Name: "Fortysoilder", Server: "CrazyLand"}
	////db.Create(&addedPlayer)
	//
	//// TODO 查询玩家
	var p Player
	db.Preload("Inventory").
		Preload("Inventory.Good").
		First(&p, 1)

	var good Good
	db.First(&good, 1)
	//axe := &PlayerItem{Good: good, Count: 233}

	for _, item := range p.Inventory {
		fmt.Println(item)
	}

	fmt.Println("========================")
	//p.Inventory = append(p.Inventory, *axe)

	for _, item := range p.Inventory {
		fmt.Println(item)
	}

	err = p.SaveInventoryToDB(db)
	if err != nil {
		fmt.Println("保存失败:", err)
		return
	}

	//marshal, err := json.Marshal(p)
	//if err != nil {
	//	fmt.Println("JSON 编码错误:", err)
	//	return
	//}
	//fmt.Println(string(marshal))

	//// TODO 更新玩家
	////fmt.Println("Before: ", p)
	////db.Model(&p).Updates(map[string]interface{}{"Server": "LzyMC", "Name": "TheAbyss"})
	////db.First(&p, 1)
	////fmt.Println("After: ", p)
	//
	//// TODO 删除玩家
	//fmt.Println("Before: ", p)
	//db.Delete(&p)
	//db.First(&p, 2)
	//fmt.Println("After: ", p)
}

func pushDataIntoDataBaseTest() {
	// 要发送的数据结构（可以来自你的 model.User）
	data := map[string]interface{}{
		"id":        2,
		"nickname":  "吃饭星人",
		"signature": "我爱吃饭饭饭",
		"avatar":    "../logo/avatar3.png",
	}

	// 将 map 转为 JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("JSON 编码错误:", err)
		return
	}

	// 发送 POST 请求
	resp, err := http.Post("http://localhost:8080/user/update", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("关闭响应体失败:", err)
		}
	}(resp.Body)

	// 打印响应状态
	fmt.Println("状态码:", resp.Status)

	// 读取响应内容
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("解析响应失败:", err)
		return
	}

	fmt.Println("响应内容:", result)
}
