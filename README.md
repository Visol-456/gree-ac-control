# gree-ac-control

格力空调局域网控制 skill。不装格力+ App，不碰云端，直接在局域网里用 UDP 7000 端口控制格力 WiFi 空调——查状态、开关机、调温度风速，一条命令的事。

格力 WiFi 模块用的是自家私有协议（UDP 7000 + AES-128-ECB/GCM 加密），协议细节早已被社区逆向公开。这个 skill 把最核心的握手和控制流程整理成一个 300 多行的 Python CLI，依赖只有 pycryptodome。

## 前置条件：先让空调连上你家WiFi

本工具走的是**局域网**协议，空调必须已经连上你家 WiFi，否则扫描不到它。

格力 WiFi 模块出厂默认没联网，**第一次必须用官方「格力+」App 配网**：

1. 空调通电开机，用遥控器或面板把空调切到 WiFi 配置模式（不同型号入口不同：遥控器「WiFi/智能」键、面板长按、或 App 内引导提示）
2. 手机装「格力+」App，注册/登录账号，添加设备
3. App 会引导你输入家里 WiFi 的 SSID 和密码——注意格力模块通常**只支持 2.4GHz**，连 5GHz 会失败或搜不到，配网时手机最好也连着同一个 2.4G 网络
4. 配网成功后 App 里能远程控制——这时它才在局域网里，本工具才能扫到它

配网只需做一次，之后断电重启也会自动连回 WiFi。二手/搬家的空调可能连着上一家的 WiFi，先长按重置 WiFi 再重新配网。配完网之后日常控制完全可以用本工具，**不需要再开格力+ App**。

## 快速开始

```bash
pip install pycryptodome   # Windows 用 python 或 py -3 代替 python3

# 1. 扫描局域网里的空调（要和空调在同一个WiFi下）
python3 scripts/gree_ac.py list
# 输出: 192.168.x.x: mac=xxxxxxxxxxxx bc=xxxx mid=11002
# 找不到设备？检查：同一WiFi、防火墙放行 UDP 7000、路由器没开 AP 隔离；
# 路由器禁广播时加 --sweep 192.168.x.0/24 逐台单播

# 2. 绑定一台，拿到它的专属key（自动保存到 ~/.config/gree-ac-control/devices.json，默认不打印key明文）
python3 scripts/gree_ac.py bind 192.168.x.x
# 输出: bind ok, saved to /home/user/.config/gree-ac-control/devices.json (chmod 600)
# 想手动管理key用 --no-save（会打印明文）或 add 命令

# 2b. 手动添加设备（已有mac和key时）
python3 scripts/gree_ac.py add 192.168.x.x xxxxxxxxxxxx xxxxxxxx

# 3. 查状态
python3 scripts/gree_ac.py status 192.168.x.x

# 4. 开空调（制冷26度低风速）
python3 scripts/gree_ac.py set 192.168.x.x Pow=1 Mod=1 SetTem=26 WdSpd=1

# 5. 关机
python3 scripts/gree_ac.py set 192.168.x.x Pow=0
```

设备配置存 `~/.config/gree-ac-control/devices.json`（`$GREE_DEVICES` 可改路径），不写死在脚本里、不进 git，写入时尽力 chmod 600。注意：`os.chmod` 在 Windows 上语义不同（只影响只读位），不过该路径在用户目录下，Windows 默认 ACL 一般只有当前用户可读；若想额外收紧，可手动 `icacls "%USERPROFILE%\.config\gree-ac-control\devices.json" /inheritance:r /grant:r "%USERNAME%:(R,W)"`。

## 参数说明

| 字段 | 含义 |
|------|------|
| `Pow` | 0=关 1=开 |
| `Mod` | 0=auto 1=cool 2=dry 3=fan 4=heat |
| `SetTem` | 设定温度（配 `TemUn`，0=℃ 1=℉） |
| `WdSpd` | 0=auto 1=low 2=med-lo 3=med 4=med-hi 5=high |
| `Tur` | 强劲模式 |
| `Quiet` | 静音 |
| `SwhSlp` | 睡眠模式 |
| `Lig` | 指示灯 |
| `Blo` | 干燥（X-Fan） |

## 测试

```bash
python3 -m unittest discover -s tests
```

UDP 收发已 mock，26 个用例覆盖 ECB/GCM 加解密、配置读写、list/bind/status/set 的异常分支（脏响应、缺字段、超时、非法字段、非整数、Windows ConnectionResetError、sendto 失败、解密失败单条提示）。无需真实空调即可跑。

## 目录

```
SKILL.md                       # skill 主文档（使用说明 + 协议要点 + 坑）
scripts/gree_ac.py             # 主 CLI：list / bind / add / status / set
scripts/gree_crypto_demo.py    # 加密原理演示（自包含，无真实设备也能跑）
docs/protocol-crypto.md        # 协议加密原理深度解析
tests/test_gree_ac.py          # 单测（mock UDP）
```

## 协议速览

- 通信：UDP 7000，外层 JSON 明文，`pack` 字段装 AES-128-ECB 加密内容（新固件可能是 AES-GCM，响应带 `tag` 字段，脚本自动识别）
- 通用 key `a3K8Bx%2r8Y7#xDh` 所有设备出厂内置（社区逆向公开）
- 流程：scan（明文）→ bind（通用key加密）→ 拿到设备专属 key → 日常用专属 key
- 详细原理、抓包示例、GCM 新版分支见 [docs/protocol-crypto.md](docs/protocol-crypto.md)

## 安全提示

这套协议的安全性约等于没有：通用 key 全世界一样，任何在你家局域网里的人都能 scan → bind → 拿到设备 key → 控制你的空调。没有认证、没有防重放。介意的话别把空调接到不信任的网络里——这也是格力至今没修的老毛病。

## License

MIT
