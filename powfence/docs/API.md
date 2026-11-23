# 租户 API 契约

基址取决于传输方式：Unix socket（`/run/powfence/powfence.sock`）、
vsock（`<host-cid>:<port>`）或回环 TCP（`http://127.0.0.1:9100`）。

所有指标端点都需要请求头：

```
Authorization: Bearer <tenant-token>
```

API **不接受任何查询参数**：窗口长度、聚合范围、量化粒度、ε 全部由
服务端策略固定。允许租户自选这些值会重新打开侧信道（例如请求
毫秒级窗口）。

## GET /v1/metrics

返回最近一个**已结束**聚合窗口的完整读数。同一窗口内的重复请求
返回字节级相同的内容（快照缓存，不额外消耗隐私预算）。

```json
{
  "window_start": "2026-11-22T19:48:11Z",
  "window_end":   "2026-11-22T19:48:12Z",
  "energy_joules": 121,
  "average_power_watts": 121,
  "freq_mhz": 2800,
  "nominal_mhz": 2500,
  "max_mhz": 3500,
  "epsilon_spent": 0.09997
}
```

| 字段 | 说明 |
| --- | --- |
| `window_start/end` | 窗口边界（UTC），也是缓存键 |
| `energy_joules` | 窗口能量增量，聚合+裁剪+DP+量化后的值；省略表示策略未启用 |
| `average_power_watts` | 由能量除以窗长派生，无额外信息 |
| `freq_mhz` | 窗口平均频率（nominal-only 时为静态常量） |
| `nominal_mhz` / `max_mhz` | CPUID 静态值，不含密钥信息 |
| `epsilon_spent` | 本次释放记账的 ε（缓存命中为 0） |

## GET /v1/metrics/energy 与 /v1/metrics/freq

字段子集版本，行为与 `/v1/metrics` 相同，便于只签一类数据的采集器。

## GET /v1/budget

返回当前策略参数与预算信息（非硬件数据，无泄露面）：

```json
{
  "policy": "standard",
  "epoch_seconds": 3600,
  "epoch_budget": 360,
  "rate_per_second": 2,
  "energy_window_s": 1,
  "frequency_window_s": 1
}
```

## GET /healthz

无需认证，存活探针。

## 错误响应

| 状态码 | 含义 | 处置 |
| --- | --- | --- |
| 401 | 缺失/错误 Bearer 令牌 | 检查令牌；重复触发会产生审计告警 |
| 429 `rate_limited` | 超过令牌桶速率 | 按 `Retry-After` 退避，缓存窗口内无需重试 |
| 429 `budget_exhausted` | 本 epoch 隐私预算用尽 | 等待 epoch 滚动（默认整点） |
| 500 | 宿主机采集故障 | 联系云平台；守护进程会跳过坏 tick 而非造假数据 |

## 客户端建议

- 按窗口节奏轮询（默认 1 s 一次即可，更快只会收到缓存或 429）；
- 节能调度使用 6+ 窗口滚动均值，可把噪声误差降到 1% 以内；
- 不要把单次读数当作高精度计量值使用；该接口是监控遥测，不是计费表。
