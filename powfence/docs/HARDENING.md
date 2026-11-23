# 部署加固清单

powfence 只能净化经过它的数据；任何绕过它的计数器访问都会使防护失效。

## 1. 阻断绕过路径

- 现代 Linux 内核已把 RAPL `energy_uj` 限制为特权读取（mode 0400，
  Platypus 缓解）。确认：

  ```bash
  find /sys/class/powercap -name energy_uj -exec ls -l {} \;
  find /sys/class/hwmon -name 'energy*_input' -exec ls -l {} \;
  ```

  任何全局可读（other 位含 r）的节点都必须通过 udev 规则收紧：

  ```udev
  # /etc/udev/rules.d/99-powfence.rules
  SUBSYSTEM=="powercap", KERNEL=="intel-rapl*", RUN+="/bin/chmod -R 0400 /sys/class/powercap/$kernel"
  ```

- 虚拟机配置中**不得**透传 RAPL/电源管理 MSR、不得挂载 powercap sysfs、
  不得向 guest 暴露 `/dev/cpu/*/msr`；
- 内核启动行确认禁用不需要的 PMU 透传，容器场景使用 seccomp 拦截
  `perf_event_open` 对能量事件的访问；
- 定期审计：在一台宿主机上以 nobody 身份尝试读取全部能量/频率节点，
  预期全部 permission denied。

## 2. 进程与文件权限

- 以独立的 `powfence` 系统用户运行，仅授予读取 sysfs 所需能力
  （通常不需要任何 capability；文件权限足够时不用 root）；
- 配置文件 mode `0600`，属主 `powfence`（内含 Bearer 令牌）；
- Unix socket 目录 mode `0750`，socket 文件 mode `0660`（守护进程
  已自动 chmod），通过组身份授权本地代理客户端；
- 审计日志目录 `0750`，日志文件 `0640`，并配置 rsyslog/journal 外发。

参考 unit：

```ini
# /etc/systemd/system/powfence.service
[Unit]
Description=Power/frequency telemetry isolation proxy
After=network.target

[Service]
User=powfence
Group=powfence
ExecStart=/usr/local/sbin/powfence -config /etc/powfence/config.json
AmbientCapabilities=
CapabilityBoundingSet=
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_UNIX AF_VSOCK
ReadWritePaths=/run/powfence /var/log/powfence
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## 3. 传输选择（优先级）

1. **AF_VSOCK**：guest 与 host 间无网络栈暴露，首选；
2. **Unix domain socket**：同机 sidecar/代理转发，loopback 之外不可达；
3. **loopback TCP**：仅实验用途，守护进程硬性拒绝非回环绑定；
   生产确需跨网络时，在前置 mTLS sidecar 后连接，不要开放裸端口。

## 4. 令牌与认证

- 每个租户独立 Bearer 令牌，至少 32 字节随机值
  （`openssl rand -hex 32`），配置校验强制最短 16 字符；
- 比较使用常量时间函数（`crypto/subtle.ConstantTimeCompare`）；
- 令牌轮换：新增临时令牌 → 客户端切换 → 移除旧令牌，重载即可
  （SIGHUP 重载在路线图上；当前为滚动重启）。

## 5. 审计与告警

- 所有 `deny_rate` / `deny_budget` / `deny_auth` 事件进 SIEM；
- 告警建议：单租户每分钟 deny_auth > 5（令牌枚举）、
  deny_budget 持续出现（探测行为或配置过紧）、
  守护进程生命周期事件（意外重启可能意味着被干扰）。

## 6. 上线前检查单

- [ ] `powfence -validate` 通过
- [ ] `powfence-selftest` 与 `powfence-attackcheck` 通过并归档 JSON
- [ ] 以非特权用户验证所有能量节点不可读
- [ ] guest 配置无 MSR/powercap/PMU 透传
- [ ] 审计日志可写入且已配置外发
- [ ] 配置文件与 socket 权限符合第 2 节
- [ ] CPU 微码为包含 Platypus/Hertzbleed 缓解的版本
