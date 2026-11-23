# 审计事件 Schema

审计日志为 JSON Lines（每行一个事件），路径由配置 `audit_path` 指定。
字段顺序稳定，可直接接入 SIEM 解析。

## 事件类型

| `action` | 触发时机 | 关键附加字段 |
| --- | --- | --- |
| `release` | 每次向租户释放窗口快照 | `epsilon`, `window_sec`, `policy` |
| `deny_rate` | 令牌桶拒绝 | `policy` |
| `deny_budget` | epoch 隐私预算不足 | `policy` |
| `deny_auth` | 认证失败 | `reason`（不含令牌内容） |
| `lifecycle` | 守护进程启动/停止 | `reason` |

## 完整字段

```json
{
  "time": "2026-11-22T19:48:12.345Z",
  "tenant": "monitoring-tenant-a",
  "action": "release",
  "feature": "",
  "reason": "",
  "epsilon": 0.09997,
  "window_sec": 1,
  "policy": "standard"
}
```

- `time`：UTC RFC3339，由审计器统一加盖；
- `tenant`：策略中的非机密 `label`，令牌本身绝不落盘；
- `feature`：保留字段，当前版本一次释放同时含能量与频率，留空；
- 省略字段在 JSON 中按 `omitempty` 不出现，不要假设字段总存在。

## 运营用法

1. **预算对账**：对同一 `(tenant, epoch)` 求和 `epsilon`，结果必须
   ≤ 策略的 `epoch_budget_epsilon`。这是对台账实现的独立外部核验；
2. **攻击探测**：`deny_rate` 与 `deny_budget` 的突发是侧信道扫描的
   典型信号，按 HARDENING.md 第 5 节配置告警；
3. **追责**：`lifecycle` 与 `release` 共同证明任意时刻生效的策略名，
   配合配置文件的版本管理可重建每次释放适用的参数集。

## 日志完整性

审计器设计为永不阻塞释放路径（写入失败只计数、不 panic）。因此
宿主机级别的防篡改需要靠外部机制：journald 远程转发、带外日志
接收器或文件完整性监控。日志文件本身不包含密钥材料或令牌。
