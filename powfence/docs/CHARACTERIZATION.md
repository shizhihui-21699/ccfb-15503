# 硬件表征流程：测定信号灵敏度

`signal_max_delta_joules` 与 `signal_max_delta_mhz` 是 signal_bounded
模式全部保证的支点。本文档给出可复现的实测方法。

## 1. 目标量

- $\Delta_E$：一次受保护密码操作在**一个聚合窗口**内可引起的封装能量
  增量最大变化（焦耳）；
- $\Delta_F$：同类操作在窗口平均频率上的最大偏移（MHz）。

注意区分操作级信号与窗口级信号：操作只占窗口的一小部分，
窗口级 $\Delta_E \approx \Delta P \times t_{op}$。

## 2. 测试环境

- 待测 CPU  stepping 的裸金属宿主机，关闭睿频以外的调频干预
  （或明确记录调频策略）；
- 以 root 直接读 `/sys/class/powercap/intel-rapl:*/*/energy_uj`
  （Intel）或 `/sys/class/hwmon/hwmon*/energy*_input`（AMD），
  频率读 `cpufreq/scaling_cur_freq`；
- 表征工具与生产代理使用相同的采样间隔（默认 100 ms）。

## 3. 差分测量协议

1. 准备两组工作负载，**唯一差异**是密码操作的密钥材料：
   - A 组：固定全零密钥执行目标算法 $N$ 次；
   - B 组：固定全一密钥（或随机密钥集）执行同一算法 $N$ 次。
   建议 $N \ge 10^5$，覆盖 SMT 开/关、不同封装温度、不同背景负载
   （空闲 / 典型混部 / 高压力）三档工况。
2. 每次操作前后各取一个能量计数器差值，并记录操作期间的频率轨迹；
3. 对每档工况分别计算两组样本分布的高分位差
   $Q_{99.5}(B)-Q_{0.5}(A)$（取绝对值的双侧包络）；
4. 取所有工况中的最大值作为原始信号界。

## 4. 安全余量与配置值

```
signal_max_delta_joules = max(实测窗口级能量界) × 3
signal_max_delta_mhz    = max(实测窗口级频率界) × 3
```

3× 余量吸收测量误差、固件/微码更新后的漂移、未覆盖工况。
每次微码更新、BIOS 升级或更换 CPU stepping 后重做第 3 节。

## 5. 验收

- 将测定值写入策略后运行 `powfence-selftest -windows 500`，
  连续 10 个不同种子必须全部通过；
- 再用真实录制的操作轨迹（而非仿真器）回放攻击分类器，
  AUC 必须落在 [0.45, 0.55] 且 d' < 0.5；
- 若任一验收失败，退回 `full_range` 模式或 nominal-only 频率，
  不得带着未通过的灵敏度上线。

## 6. 无法完成表征时

- 频率：直接使用 `expose_nominal_only`，零依赖、零泄露；
- 能量：使用 `dp_mode: "full_range"`，灵敏度 = `envelope_watts ×
  window_seconds`，并向租户说明该档位的噪声水平。
