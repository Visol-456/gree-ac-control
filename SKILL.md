---
name: gree-ac-control
description: 格力空调局域网控制（UDP 7000 协议）——查状态、开关机、调温度。用户说"开空调/关空调/查空调"时用。
version: 1.0.0
author: visolin
license: MIT
metadata:
  hermes:
    tags: [smart-home, gree, air-conditioner, udp, reverse-engineering]
---

# 格力空调局域网控制

## When to Use

- 用户想不开格力+ App 就控制家里格力 WiFi 空调（查状态 / 开关机 / 调温度风速）
- 用户问格力空调能不能接入本地控制、Home Assistant、脚本或 AI 助手
- 需要演示/讲解格力私有协议（UDP 7000 + AES）的加密原理

## 前置条件：先让空调连上你家WiFi（必做）

本工具走的是**局域网**协议，空调必须已经连上你家 WiFi，否则扫描不到它。
格力 WiFi 模块出厂默认没联网，**第一次必须用官方「格力+」App 配网**：

1. 空调通电开机，用遥控器或面板把空调切到 WiFi 配置模式
   （不同型号入口不同：遥控器「WiFi/智能」键、面板长按、或 App 内引导提示）
2. 手机装「格力+」App，注册/登录账号，添加设备
3. App 会引导你输入家里 WiFi 的 **SSID 和密码**——注意：
   - 格力模块通常**只支持 2.4GHz**，连 5GHz 会失败或搜不到
   - 配网时手机最好也连着同一个 2.4G 网络
4. 配网成功后空调指示灯状态变化，App 里能远程控制——这时它才在局域网里，
   本工具才能 `list` 扫到它

配网只需做一次，之后空调断电重启也会自动连回 WiFi。
如果空调是二手/搬家的，可能连着上一家的 WiFi——先长按重置 WiFi 再重新配网。
配完网之后，日常控制完全可以只用本工具，**不需要再开格力+ App**。

## 快速使用

```bash
# 依赖（Windows 用 python 或 py -3 代替 python3）
pip install pycryptodome

# 1. 扫描局域网里的空调（要和空调在同一个WiFi下；路由器禁广播时加 --sweep）
python3 scripts/gree_ac.py list
# 输出: 192.168.x.x: mac=xxxxxxxxxxxx bc=xxxx mid=11002
# 找不到设备？检查：同一WiFi、防火墙放行 UDP 7000、路由器没开 AP 隔离

# 2. 绑定一台，拿到它的专属key（scan→bind一步完成，自动保存到 ~/.config/gree-ac-control/devices.json）
python3 scripts/gree_ac.py bind 192.168.x.x
# 输出: bind ok, saved to /home/user/.config/gree-ac-control/devices.json (chmod 600)
# 注意：默认不打印 key 明文（避免进终端日志）；想手动管理用 --no-save 或 add

# 2b. 手动添加设备（比如你已经有mac和key）
python3 scripts/gree_ac.py add 192.168.x.x xxxxxxxxxxxx xxxxxxxx

# 3. 查状态
python3 scripts/gree_ac.py status 192.168.x.x

# 4. 开空调（制冷26度低风速）
python3 scripts/gree_ac.py set 192.168.x.x Pow=1 Mod=1 SetTem=26 WdSpd=1

# 5. 关机
python3 scripts/gree_ac.py set 192.168.x.x Pow=0
```

命令：`list [--sweep CIDR]`（发现设备）`bind <ip> [--no-save]`（绑定拿key）`add <ip> <mac> <key>`（手动录入）`status [ip]`（查状态）`set <ip> k=v ...`（控制）。

设备配置存在 `~/.config/gree-ac-control/devices.json`（可用 `$GREE_DEVICES` 改路径），
不写死在脚本里，也不进 git。Windows 下命令用 `python` 或 `py -3` 代替 `python3`；
第一次扫不到设备先放行防火墙的 UDP 7000 入站。

## 参数说明（status/set 字段）

- `Pow`: 0=关 1=开
- `Mod`: 0=auto 1=cool 2=dry 3=fan 4=heat
- `SetTem` + `TemUn`: 设定温度（0=℃，1=℉）
- `WdSpd`: 0=auto 1=low 2=med-lo 3=med 4=med-hi 5=high
- `Tur`=强劲, `Quiet`=静音, `Health`, `SwhSlp`=睡眠, `Lig`=指示灯, `Blo`=干燥(X-Fan)

## 协议要点（逆向自 tomikaa87/gree-remote）

- **UDP 7000**，设备不监听任何 TCP 端口。
- 消息 = 外层明文 JSON：`{"cid":"app","i":N,"t":"pack","uid":0,"tcid":<mac>,"pack":<b64>}`。
- 内层 pack：JSON → **AES128-ECB + PKCS7** → Base64。
- **通用key：`a3K8Bx%2r8Y7#xDh`**（16字节！网传 `a3K8Bx%2r8t7Bw%2F` 是错的，会报 Incorrect AES key length）。
- 流程：scan（明文 `{"t":"scan"}`）→ 设备回加密 dev 包 → bind（通用key加密 `{"mac":...,"t":"bind","uid":0}`）→ 拿设备专属 key → 之后 status/cmd 都用设备 key 加密。
- 状态查询：`{"cols":[...],"mac":...,"t":"status"}`；控制：`{"opt":[...],"p":[...],"t":"cmd"}`，回 `r:200` 为成功。

## 深度资料

- `docs/protocol-crypto.md` —— 协议加密原理深度解析（三层套娃结构、AES全程流程、通用key→设备key握手模型、ECB弱点、GCM分支、抓包示例）
- `scripts/gree_crypto_demo.py` —— 加密原理自包含演示（无真实设备也能跑）

## 坑

- 关机时也能查状态（WiFi 模块常电）。
- 设备对广播 scan 也响应单播 scan，直接对 IP 发即可，不用广播。
- scan 响应 JSON 可能带尾部垃圾，取 `data[0:data.rfind(b'}')+1]`。
- 新版固件可能用 AES-GCM（响应带 `tag` 字段）：key `{yxAHAY_Lm6pbC/<`，IV `\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13`，AAD `qualcomm-test`，明文可能带 `\xff` 填充。脚本自动识别 tag 走 GCM 解密；遇到解密失败的脏包会跳过并提示，不影响整体运行。

## Environment & dependencies

| 依赖 | 必需？ | 说明 |
|------|--------|------|
| pycryptodome | 必需 | AES 加解密 |
| Python 3.8+ | 必需 | 无其他第三方依赖 |

## 安全提示

这套协议安全性约等于零：通用 key 全世界一样，任何在你家局域网里的人都能 scan → bind → 拿设备 key → 控制你的空调。没有认证、没有防重放。别把空调接进不信任的网络。

## 参考实现

- https://github.com/tomikaa87/gree-remote（PythonCLI/gree.py 有完整 ECB+GCM 双模式代码）
- Home Assistant: https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent
