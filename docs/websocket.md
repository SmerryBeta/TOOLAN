# WebSocket 推送协议

后端地址：

```text
ws://<server-host>:8000/ws
```

如果服务部署为 HTTPS，对应使用：

```text
wss://<server-host>/ws
```

## 通用事件结构

服务端所有 WebSocket 消息都是 JSON 文本帧，外层结构固定：

```json
{
  "type": "message",
  "time": "2026-06-02T20:30:00+08:00",
  "payload": {}
}
```

字段说明：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `type` | string | 事件类型。安卓端按该字段分流处理。 |
| `time` | string | 服务端推送时间，RFC3339 格式。 |
| `payload` | object | 事件内容。不同 `type` 的结构见下文。 |

### 握手参数 `?device=`

连接 `/ws` 时可携带 `?device=android` 声明设备身份。目前仅识别 `android`，
其余取值一律视为未声明（浏览器等）。声明了 `android` 的连接才会收到定向事件
（当前为 `file.sync_offer`）；未声明的连接不会收到，广播事件（message 等）
不受影响。

## 文件同步邀请事件

### `file.sync_offer`

由 `POST /upload?sync=1` 上传成功后触发，**只定向发送给 `?device=android` 客户端**
（无安卓客户端在线时不发送，上传响应的 `delivered` 字段为 0）。安卓端应展示
"接受 / 拒绝"界面，用户点"接受"后才凭 `files[].url` 下载。

```json
{
  "type": "file.sync_offer",
  "time": "2026-11-06T12:00:00+08:00",
  "payload": {
    "batchId": "9f2c1a7b33e05d16",
    "files": [
      {
        "name": "a.png",
        "size": 1234567,
        "mime": "image/png",
        "kind": "image",
        "path": "sub/a.png",
        "url": "/api/sync/file?ftoken=<一次性凭证>"
      }
    ]
  }
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `payload.batchId` | 批次标识，每次上传一个批次（1 个文件）；多文件合并展示由客户端聚合 |
| `files[].name` | 文件名 |
| `files[].size` | 文件字节数（进度展示可用） |
| `files[].mime` | MIME 类型（可空） |
| `files[].kind` | 分区：`image` 或 `file` |
| `files[].path` | 仓库内相对路径 |
| `files[].url` | 相对下载地址，需拼接客户端自己配置的服务器地址前缀 |

`url` 中的 `ftoken` 是服务端签发的一次性下载凭证：10 分钟内有效、最多 5 次
下载、仅绑定该单个文件；`GET /api/sync/file?ftoken=` 端点凭此凭证放行（仍受
限流），无需携带会话令牌。凭证过期或超次后该地址返回 404。

## 消息通知事件

### `message`

由 `POST /message` 触发，用于普通消息提示。

```json
{
  "type": "message",
  "time": "2026-06-02T20:30:00+08:00",
  "payload": {
    "source": "message",
    "title": "升级提醒",
    "msg": "TOOLAN 软件需要准备升级",
    "content": "TOOLAN 软件需要准备升级",
    "time": "2026-06-02T20:30:00+08:00"
  }
}
```

安卓端展示通知时优先读取：

| 字段 | 说明 |
| --- | --- |
| `payload.title` | 通知标题 |
| `payload.msg` | 通知正文 |

`payload.content` 与 `payload.msg` 内容相同，是为了兼容当前网页端。

### `notification`

由 `POST /notify` 触发，结构与 `message` 相同，只是 `payload.source` 为 `notification`。

## 日期提醒事件

### `reminder.created`

由 `POST /api/reminders` 创建提醒时触发。该事件用于同步提醒列表，不建议直接弹系统通知。

```json
{
  "type": "reminder.created",
  "time": "2026-06-02T20:10:00+08:00",
  "payload": {
    "id": "1f2e3d4c5b6a7980",
    "title": "TOOLAN 升级",
    "content": "在这天我要完成TOOLAN软件的升级工作",
    "remindAt": "2026-06-02T20:30:00+08:00",
    "done": false,
    "createdAt": "2026-06-02T20:10:00+08:00"
  }
}
```

### `reminder.due`

提醒到期时触发。安卓端应该对该事件弹系统通知。

后端会把提醒日期格式化到 `payload.title`，格式为：

```text
YYYY.M.D 到了
```

例如用户设置 `2026-06-02` 的提醒，内容为 `在这天我要完成TOOLAN软件的升级工作`，推送如下：

```json
{
  "type": "reminder.due",
  "time": "2026-06-02T20:30:00+08:00",
  "payload": {
    "source": "reminder",
    "title": "2026.6.2 到了",
    "msg": "在这天我要完成TOOLAN软件的升级工作",
    "content": "在这天我要完成TOOLAN软件的升级工作",
    "time": "2026-06-02T20:30:00+08:00",
    "reminderId": "1f2e3d4c5b6a7980",
    "remindAt": "2026-06-02T20:30:00+08:00"
  }
}
```

安卓端展示通知时使用：

| 字段 | 说明 |
| --- | --- |
| `payload.title` | 通知标题，例如 `2026.6.2 到了` |
| `payload.msg` | 通知正文，例如 `在这天我要完成TOOLAN软件的升级工作` |
| `payload.reminderId` | 提醒 ID，可用于后续回写已完成状态 |
| `payload.remindAt` | 原始提醒时间 |

### `reminder.updated`

由 `PATCH /api/reminders/:id` 修改完成状态时触发。用于同步提醒列表，不建议直接弹系统通知。

### `reminder.deleted`

由 `DELETE /api/reminders/:id` 删除提醒时触发。

```json
{
  "type": "reminder.deleted",
  "time": "2026-06-02T20:30:00+08:00",
  "payload": {
    "id": "1f2e3d4c5b6a7980"
  }
}
```

## 安卓端处理建议

1. 建立 `ws://<server-host>:8000/ws?device=android` 连接（声明设备身份才能收到定向事件）。
2. 收到文本帧后解析 JSON。
3. 只对 `type == "message"`、`type == "notification"`、`type == "reminder.due"` 弹系统通知。
4. 通知标题使用 `payload.title`。
5. 通知正文使用 `payload.msg`。
6. 断线后做自动重连，建议 3 到 5 秒退避重连。
7. 对 `type == "file.sync_offer"` 不走通用系统通知：展示文件清单与"接受 / 拒绝"
   （前台弹框、后台通知带按钮均可），用户接受后再凭 `files[].url` 下载；
   凭证有时效，过晚接受会 404，失败时应提示用户改从仓库页下载。
