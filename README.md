# TOOLAN

这是一个 Go 语言后端项目。名称可以是 Tool & LAN 合并一下不就是 TOOLAN 了吗！
<img width="1000" alt="image" src="https://github.com/user-attachments/assets/dbf838b3-c222-430b-bc4c-a6f4b3249e65" />

不过一般都是我一个人在用，据说QQ之类的国产软件都接入公安了，如果你传一些不雅的图或者极度隐私的图直接通过国内的社交工具就不安全了。所以，在内网仓库藏、传一点18+之类的危险的图，敬茶蜀黍看不到 :P，管不到。管不到，根本管不到！而且内网用还不需要流量，传大文件舒服的很！
<img width="1000" alt="image" src="https://github.com/user-attachments/assets/0b6a98b7-8298-477e-baf8-d1c45bdfe0b3" />

## 项目结构

```
.
├── model/           #（当前未使用）
│   ├── post.go      # 文章模型
│   └── user.go      # 用户模型
├── reviewer/ # 没什么用（当前未使用）
│   └── interface.go # 评审接口
├── static/
│   ├── UploadImage.vue # 图片上传组件
│   ├── app.js          # 应用脚本
│   ├── index.html      # 主页
│   ├── store.html      # 存储页面
│   └── style.css       # 样式文件
├── test/              # （当前未使用）
│   ├── simple_test.go # 简单测试
│   └── test.go        # 测试文件
├── util/              # 工具包（当前未使用）
│   ├── auth.go
│   ├── file_loader.go
│   ├── linker.go
│   └── secure.go
├── config.yml         # 配置文件
├── go.mod             # Go模块定义
├── go.sum             # Go模块校验
├── main.go            # 主程序入口
├── package.json       # Node.js包定义
├── package-lock.json  # Node.js包锁定
└── README.md          # 项目说明
```

## 关于util包

注意：`util` 包目前处于未使用状态，其中包含的以下文件暂时没有被项目引用：

- `auth.go` - 认证相关工具
- `file_loader.go` - 文件加载器
- `linker.go` - 链接器
- `secure.go` - 安全相关工具

这些文件保留供将来可能的功能扩展使用。

## 运行项目

```bash
go run main.go
```

## 依赖

项目使用 Go Modules 进行依赖管理，详情请查看 `go.mod` 文件。
