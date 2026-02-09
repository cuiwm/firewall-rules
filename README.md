# firewall-rules

Production-grade firewall and fail2ban automation scripts using iptables and ipset.

**语言 / Language**:  
[English](#english) | [中文](#中文)

---

## English

### Overview

This repository provides production-ready shell scripts for firewall hardening
and fail2ban integration on Linux servers.

The scripts focus on predictable behavior, reboot safety, and compatibility
across iptables-nft and legacy environments.

---

### Quick Install

```sh
SSH_MODE=public bash <(curl -Ls https://raw.githubusercontent.com/cuiwm/firewall-rules/refs/heads/main/fw-22-80-443-ipset.sh) install

bash <(curl -Ls https://raw.githubusercontent.com/cuiwm/firewall-rules/refs/heads/main/fail2ban-ipset-setup.sh) install
```
### Included Scripts

#### 1. fw-22-80-443-ipset.sh

Baseline firewall setup using **iptables + ipset**.

**Purpose**
- Restrict inbound traffic by default
- Protect common service ports:
  - 22 (SSH)
  - 80 (HTTP)
  - 443 (HTTPS)

**Modes**
```bash
install     Apply firewall baseline
uninstall   Remove firewall rules created by this script
```

#### 2. fail2ban-ipset-setup.sh

Configure fail2ban to use **ipset-based banning** instead of nftables native sets.

**Purpose**

- Improve compatibility across iptables backends
- Centralize ban management via ipset
- Avoid nftables set inconsistencies

**Modes**

```bash
install     Install ipset-based fail2ban actions
uninstall   Restore original fail2ban behavior
bootfix     Re-apply rules after reboot
```

------

### Requirements

- Linux (tested on Ubuntu 22.04 / 24.04)
- bash >= 4.x
- iptables (iptables-nft or legacy)
- ipset
- fail2ban >= 0.11

------

### Usage

⚠️ **All scripts must be run as root.**

```bash
sudo ./fw-22-80-443-ipset.sh install
sudo ./fail2ban-ipset-setup.sh install
```

------

### Firewall Rule Persistence 

The firewall rules created by `fw-22-80-443-ipset.sh` are applied using
**iptables and ipset**, which are **in-memory kernel rules**.

As a result:

- All firewall and ipset rules **will be cleared after a system reboot**
- This behavior is expected and is the default for iptables/ipset
- No automatic persistence is provided by default

To ensure firewall rules are restored after reboot, this project provides
a **restore mechanism based on re-executing the install logic**, instead of
restoring raw rule snapshots.

#### Recommended Approach

- Use `fw-22-80-443-ipset-restore.sh` to restore firewall rules
- The restore script simply re-runs:
```bash
  fw-22-80-443-ipset.sh install
```

* This design ensures:

  * Idempotent behavior
  * Predictable rule state
  * Easy debugging and maintenance

#### systemd Integration (Recommended)

For production systems, it is recommended to run the restore script
automatically at boot time using systemd.

A sample systemd unit file:

```ini
[Unit]
Description=Restore firewall rules (iptables + ipset)
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/opt/firewall/fw-22-80-443-ipset-restore.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable it with:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fw-iptables-restore.service
```

---

### Safety Notes

- These scripts modify system firewall and security behavior
- Incorrect usage may block SSH or network access
- Always test in non-production environments first

------

### License

This project is licensed under the **MIT License**.

Each script includes its own license header to ensure legal clarity
when copied or reused independently.

------

## 中文

### 项目简介

本仓库提供 **生产级** 的 Linux 运维 Shell 脚本，
用于防火墙基线配置及 fail2ban 与 ipset 的集成。

设计目标是：

- 行为可预测
- 重启后规则可恢复
- 同时兼容 iptables-nft 与 legacy 环境

------
### 快速安装 

```sh
SSH_MODE=public bash <(curl -Ls https://raw.githubusercontent.com/cuiwm/firewall-rules/refs/heads/main/fw-22-80-443-ipset.sh) install

bash <(curl -Ls https://raw.githubusercontent.com/cuiwm/firewall-rules/refs/heads/main/fail2ban-ipset-setup.sh) install
```

### 包含脚本

#### 1. fw-22-80-443-ipset.sh

基于 **iptables + ipset** 的防火墙基线脚本。

**功能**

- 默认限制入站流量
- 保护常见服务端口：
  - 22（SSH）
  - 80（HTTP）
  - 443（HTTPS）

**模式**

```bash
install     应用防火墙基线规则
uninstall   删除由脚本创建的防火墙规则
```

------

#### 2. fail2ban-ipset-setup.sh

将 fail2ban 的封禁逻辑切换为 **基于 ipset** 的实现方式。

**功能**

- 提高在 iptables-nft / legacy 环境下的兼容性
- 统一封禁逻辑，便于排查与维护
- 避免 nftables set 行为不一致的问题

**模式**

```bash
install     安装基于 ipset 的 fail2ban 动作
uninstall   恢复原有 fail2ban 行为
bootfix     系统重启后重新修复规则
```

------

### 环境要求

- Linux（已在 Ubuntu 22.04 / 24.04 测试）
- bash >= 4.x
- iptables（iptables-nft 或 legacy）
- ipset
- fail2ban >= 0.11

------

### 使用方式

⚠️ **所有脚本必须以 root 权限运行。**

```bash
sudo ./fw-22-80-443-ipset.sh install
sudo ./fail2ban-ipset-setup.sh install
```

------

###  防火墙规则持久化说明

`fw-22-80-443-ipset.sh` 使用 **iptables 和 ipset** 建立防火墙规则，
这些规则均为 **内核内存规则**。

因此：

* 系统重启后，所有 iptables / ipset 规则都会被清空
* 这是 iptables/ipset 的默认行为，属于正常现象
* 本项目 **默认不使用规则快照或自动持久化机制**

为了解决重启后规则丢失的问题，本项目采用了 **“重新执行 install 逻辑”**
的方式来恢复防火墙规则，而不是恢复静态规则快照。

#### 推荐方案

* 使用 `fw-22-80-443-ipset-restore.sh` 恢复防火墙规则
* 恢复脚本的核心逻辑是重新执行：

  ```bash
  fw-22-80-443-ipset.sh install
  ```
* 该设计具备以下优势：

  * 支持幂等执行（可重复运行）
  * 防火墙状态可预测、可维护
  * 便于排查和调试问题

#### systemd 启动时自动恢复（推荐）

在生产环境中，建议通过 systemd 在系统启动完成后
自动执行防火墙恢复脚本。

示例 systemd 单元文件如下：

```ini
[Unit]
Description=Restore firewall rules (iptables + ipset)
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/opt/firewall/fw-22-80-443-ipset-restore.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

启用方式：

```bash
sudo systemctl daemon-reload
sudo systemctl enable fw-iptables-restore.service
```

---

### 安全说明

- 脚本会修改系统防火墙与安全策略
- 使用不当可能导致 SSH 或网络中断
- 请优先在非生产环境中测试

------

### 许可协议

本项目采用 **MIT License**。

每个脚本文件头均包含独立的 License 声明，
以确保脚本被单独复制或复用时的法律清晰性。


------

