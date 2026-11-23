# powfence

宿主机侧的功耗/频率信息隔离代理。它在特权域读取 RAPL 能量计数器和
cpufreq 频率，经过匿名化管线后再向虚拟机租户暴露，阻断 Platypus 类
（功耗侧信道，CVE-2020-8694 / CVE-2020-8695）与 Hertzbleed 类
（频率侧信道，CVE-2022-24436 / CVE-2022-24518）的远程密钥推断攻击，
同时保留节能调度与性能分析所需的监控效用。

> 漏洞编号请在部署前对照 Intel/AMD 官方安全公告复核；本仓库引用它们
> 仅用于说明威胁类别。

## 为什么需要它

同一物理机上，受害者的密钥相关运算会让封装功耗产生毫焦级、让 CPU 频率
产生兆赫兹级的可复现偏移。拿到高频原始计数器的攻击者可通过统计分析
（需要数千到数百万样本）恢复密钥。单纯关闭计数器会破坏正常监控；
powfence 的目标是**让监控数据继续可用，但让密钥相关信号在统计上消失**。

## 防护管线（每个租户、每个窗口）

```
原始 RAPL/cpufreq 采样（100 ms tick，仅宿主机进程可见）
  → 空间聚合：所有 socket / 所有 CPU 收敛为一个标量（永不暴露单核/单域）
  → 时间聚合：固定窗口（默认 1 s，严格模式 5 s），只返回已结束的完整窗口
  → 有界影响残差裁剪：相对 DP 基线的偏移被限制在实测灵敏度内
  → 拉普拉斯机制：ε-差分隐私噪声，尺度 = 灵敏度 / ε
  → 粗量化：能量 0.5 J 粒度、频率 25 MHz 粒度（DP 输出的后处理）
  → 窗口快照缓存：窗口内任何轮询都拿到字节级相同的响应
```

另有两道独立防线：

- **令牌桶限流**：阻止高频轮询；
- **隐私预算台账**：每小时 epoch 的 ε 顺序组合超支即拒绝服务。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `cmd/powfence` | 守护进程入口 |
| `cmd/powfence-selftest` | 攻击模拟 + 统计检验（实证防护证据） |
| `cmd/powfence-attackcheck` | 负对照：确认检验能抓住弱配置 |
| `internal/policy` | 策略定义、预算组合校验 |
| `internal/source` | RAPL/sysfs 采集（Linux）与确定性 mock |
| `internal/sanitize` | 窗口聚合、裁剪、DP、量化、缓存 |
| `internal/dp` | 拉普拉斯机制、灵敏度、预算台账 |
| `internal/ratelimit` | 每租户令牌桶 |
| `internal/server` | Unix/TCP/vsock HTTP API、Bearer 认证 |
| `internal/audit` | 每次释放/拒绝的 JSON 审计行 |
| `internal/selftest` | 攻击模拟器与统计检验 |
| `configs/` | 生产示例与本地 mock 配置 |

## 快速开始（无需硬件）

```bash
go build ./...
# 本地 mock 数据源 + 回环 TCP
sudo ./powfence -config configs/powfence.mock.json
curl -H "Authorization: Bearer demo-token-0123456789abcdef0123456789" \
  http://127.0.0.1:9100/v1/metrics
```

## 防护证据

```bash
# 正对照：原始 tick 级通道可检测；standard/strict 策略下通道消失、监控误差 <5%
go run ./cmd/powfence-selftest -windows 250

# 负对照：弱噪声配置必须被检验抓住，正确配置必须保持安静
go run ./cmd/powfence-attackcheck
```

自测在 20 组独立随机种子下通过。检验方法学（Welch t、Cohen's d'、
Mann-Whitney AUC 的双检测器一致性规则）见
[`docs/GUARANTEES.md`](docs/GUARANTEES.md)。

## 文档

- [`docs/GUARANTEES.md`](docs/GUARANTEES.md) — 形式化隐私声明、邻接定义、
  组合定理、证据边界（诚实列出假设与不覆盖的攻击）
- [`docs/CHARACTERIZATION.md`](docs/CHARACTERIZATION.md) — 如何在目标硬件上
  实测 `signal_max_delta_*` 灵敏度参数
- [`docs/HARDENING.md`](docs/HARDENING.md) — 部署加固清单（sysfs 权限、
  vsock、systemd、审计外发）
- [`docs/API.md`](docs/API.md) — 租户 API 契约
- [`docs/AUDIT.md`](docs/AUDIT.md) — 审计事件 schema

## 验证状态

- `go test -race ./...` 全部通过；
- `GOOS=linux GOARCH=amd64 go build ./...` 交叉编译通过（RAPL/vsock 路径
  仅在 Linux 编译）；
- 自测与负对照均通过；macOS 上用 mock 源开发，生产采集需 Linux。
