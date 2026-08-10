# 格力协议完整字段字典（status/set 参数）

> 来源: https://github.com/tomikaa87/gree-remote (README, 社区逆向权威文档)
> 抓取日期: 2026-08-10。所有字段均为数值。

## status 请求的 cols 列表（官方格力+ App 用的字段）

```
Pow Mod SetTem WdSpd Air Blo Health SwhSlp Lig SwingLfRig SwUpDn Quiet Tur StHt TemUn HeatCoolType TemRec SvSt
```

## 字段取值

### Pow — 电源
- 0: off
- 1: on

### Mod — 模式
- 0: auto
- 1: cool
- 2: dry
- 3: fan
- 4: heat

### SetTem / TemUn — 设定温度与单位
- TemUn=0 → SetTem 为摄氏度
- TemUn=1 → SetTem 为华氏度
- **华氏度必须配合 TemRec 位**（见下方映射表），否则部分固件仍按摄氏处理

### WdSpd — 风速
- 0: auto
- 1: low
- 2: medium-low（3档机没有）
- 3: medium
- 4: medium-high（3档机没有）
- 5: high

### Air — 新风阀（非所有机型）
- 0: off
- 1: on

### Blo — 干燥/X-Fan（关后风机继续吹干，仅 Dry/Cool 可用）

### Health — 冷等离子（带负离子发生器机型）
- 0: off
- 1: on

### SwhSlp — 睡眠模式（Cool/Heat/Dry 下逐渐调温）
- 0: off
- 1: on

### Lig — 指示灯+显示屏
- 0: off
- 1: on

### SwingLfRig — 左右导风板（部分机型，如 Cooper&Hunter）
- 0: default
- 1: full swing
- 2-6: 固定位置 最左→最右

### SwUpDn — 上下导风板（完整取值，踩过坑！）
| 值 | 含义 |
|---|---|
| 0 | default |
| 1 | **全范围扫风**（不是固定位置！） |
| 2 | 固定最上 (1/5) |
| 3 | 固定中上 (2/5) |
| 4 | 固定中间 (3/5) |
| 5 | 固定中下 (4/5) |
| 6 | 固定最下 (5/5) |
| 7 | 最下区域扫风 |
| 8 | 中下区域扫风 |
| 9 | 中间区域扫风 |
| 10 | 中上区域扫风 |
| 11 | 最上区域扫风 |

**注意：要"朝上打不扫风"用 SwUpDn=2，不是 1！1 是整幅扫风。**

### Quiet — 静音（风扇最低速；Dry/Fan 模式不可用）
- 0: off
- 1: on

### Tur — 强劲（风速拉满；仅 Dry/Cool 可用；开启时 WdSpd 不可调）
- 0: off
- 1: on

### StHt — 保温模式（维持8°C防冻，长时间离家时用）
- 0: off
- 1: on

### HeatCoolType — 未知

### TemRec — 华氏度区分位（见下）

### SvSt — 节能模式
- 0: off
- 1: on

## 华氏度温度设置（TemRec 映射）

公式:
```
TemSet = round((desired_f - 32.0) * 5.0 / 9.0)
TemRec = (int)((((desired_f - 32.0) * 5.0 / 9.0) - TemSet) > 0)
```

| Units | 1 | 2 | ... | 10 | 11 | ... | 19 |
|---|---|---|---|---|---|---|---|
| Fahrenheit | 68 | 69 | ... | 77 | 78 | ... | 86 |
| Celsius | 20.0 | 20.5 | ... | 25.0 | 25.5 | ... | 30.0 |
| TemSet | 20 | 21 | ... | 25 | 26 | ... | 30 |
| TemRec | 1 | 0 | ... | 1 | 0 | ... | 0 |

（完整19档见 gree-remote README）

## TemSen — 室内温度传感器（不在默认 cols 里，需单独查）

- 查询：`{"cols":["TemSen"],"mac":...,"t":"status"}`
- **文档说值有 +40 偏移**（例：返回 65 → 实际 25°C）
- **实测（2026-08-10, 国产1.5匹挂机 mid=11002）**：TemSen=28 对应室温约 28°C（App 显示 27°），即该固件**无 +40 偏移**，直接返回温度。不同固件行为可能不同，以实测为准。

## 响应格式

status 响应：`{"t":"dat","mac":...,"r":200,"cols":[...],"dat":[...]}`，cols/dat 一一对应。

cmd 响应：`{"t":"res","mac":...,"r":200,"opt":[...],"p":[...],"val":[...]}`。
- r=200 成功；请求失败时设备可能**不回复任何内容**
- 部分固件只回 `p` 不回 `val`，两种都要处理

## 其他协议操作（附录）

### 定时调度（setT）
```
{"cmd":<mac>,"opt":"Pow","p":0,"enable":0,"hr":20,"id":0,"min":40,"name":"5363686564756c65","sec":0,"t":"setT","tz":1,"week":[0,0,1,0,0,1,0]}
```
- week 从周日开始，1=启用
- name = 名称的 ASCII 十六进制

### 设备时间
- 读：`{"cols":["time"],"mac":...,"t":"status"}` → `"dat":"2018-05-11 19:42:01"`
- 写：`{"opt":["time"],"p":["2018-05-11 19:29:38"],"sub":"","t":"cmd"}`

### 广播技巧
- 控制消息可发到**广播地址**而非设备 IP——tcid 字段负责寻址，可省去记录每台 IP
- （我们的脚本按 IP 管理，此技巧仅作参考）

### WiFi 密码长度坑
- WPA 标准支持63字符，**部分格力固件限制31字符**，超长密码会导致连不上网

### 隐私：云心跳
- 设备会定期向格力服务器（`138.91.51.53:5000` TCP）发心跳
- 防火墙拦截**可能让部分设备锁死不再响应本地请求**，拦截需谨慎
- 替代方案：GreeAC-DummyServer（emtek-at）本地假服务器
