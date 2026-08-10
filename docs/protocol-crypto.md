# 格力空调协议加密原理（深度解析）

> 用真实抓包演示过，全流程可复现。演示脚本见 `scripts/gree_crypto_demo.py`。

## 一句话模型

格力WiFi模块 = UDP 7000 + 三层套娃消息 + **AES贯穿全程，变的只是钥匙**：
**通用key**（全世界所有格力空调出厂内置）→ 握手(bind) → 拿到**设备专属key** → 日常通信。

## 消息结构（三层套娃）

```
第1层：外层JSON —— 【明文】，随便看
  {"t":"pack", "cid":"app", "i":0, "uid":0, "tcid":"<device-mac>", "pack":"<密文>"}

第2层：pack字段 —— 真正的内容，AES-128-ECB加密
  明文JSON → PKCS7补齐到16字节倍数 → AES加密 → Base64编码

第3层：钥匙 —— 两种
  ① 通用key: a3K8Bx%2r8Y7#xDh  (所有设备硬编码，社区逆向公开)
  ② 设备key: bind时空调现场发 (每台不同)
```

## 全程加密流程（AES从哪一步开始）

| 步骤 | 方向 | 明文还是密文 | 用什么key |
|---|---|---|---|
| scan | 发 → 空调 | **明文** `{"t":"scan"}`（唯一裸奔的一步） | 无 |
| scan响应 | 空调 → 收 | AES密文（dev包：mac/bc/mid） | 通用key |
| bind | 发 → 空调 | AES密文 `{"mac":...,"t":"bind","uid":0}` | 通用key |
| bindok响应 | 空调 → 收 | AES密文，内含**设备专属key** | 通用key |
| status/cmd | 双向 | AES密文 | **设备专属key** |

关键认知：**ECB 老固件里 AES 算法从头到尾没换过，变的是密钥**（GCM 新固件另说，见下文）。
bind = 用万能钥匙开锁，空调在锁里塞给你专属钥匙；之后插专属钥匙开同一把锁。

## 实测数据（抓包示例）

真实scan响应（1.5匹挂机，192字节密文 = 12个AES分组）：
- Base64密文 → AES-128-ECB通用key解密 → PKCS7去padding →
  `{"t":"dev","cid":"","bc":"<device-broadcast-id>__","mac":"<device-mac>","mid":"11002",...}`
- 明文157字节，末尾补了15个 `\x0f`（PKCS7规则：补N个0xN）
- `mid=11002` = 1.5匹挂机型号代码

## 为什么能逆向/为什么不安全

1. **ECB模式**：同样的明文块 → 同样的密文块（最弱的分组模式）。
   格力图省事，但也让模式识别、重放攻击变得容易。
2. **通用key硬编码在所有设备**：任何人在你家局域网内都能
   scan → bind → 拿设备key → 完全控制你的空调。无人认证、无防重放。
   这就是典型智能家居IoT安全漏洞，格力至今未修。
3. 数据包无签名、无时间戳防重放，密文抓下来改改就能重放。

## 新版固件：GCM 分支

- 部分新固件响应带 `tag` 字段 → 说明走 **AES-GCM** 模式：
  - key: `{yxAHAY_Lm6pbC/<`
  - IV: `\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13`
  - AAD: `qualcomm-test`
  - 解密后明文可能带 `\xff` 填充，需 strip
- 判断方法：scan响应 JSON 里有没有 `tag` 字段。
- 实测多数国产2020-2023年产机型（mid=11002）都是 ECB。

## 参考实现

- https://github.com/tomikaa87/gree-remote —— PythonCLI/gree.py 有 ECB+GCM 双模式完整代码
- Home Assistant: RobHofmann/HomeAssistant-GreeClimateComponent
