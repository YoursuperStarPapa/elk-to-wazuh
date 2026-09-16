# Wazuh Alerting Monitor — 标准化创建模板

## 概述

本文档提供 Wazuh Dashboard（基于 OpenSearch Alerting Plugin）创建 Monitor 的标准化流程，适用于安全告警监控场景。

---

## 一、数据流关系

```
原始日志 → Wazuh Agent → Decoder 解码 → Rule 匹配 → Alert 写入 wazuh-alerts-* 索引
                                                           ↓
                                          OpenSearch Alerting Monitor 查询
```

**关键点**：Monitor 的 query 查的是 `wazuh-alerts-*` 索引中的告警文档，字段名取决于 Wazuh 解码后的结构。

---

## 二、创建前准备：确认字段结构

### 方法一：Discover 查看

Wazuh Dashboard → **Discover** → 选 `wazuh-alerts-*` → 找到目标告警 → 展开查看字段。

### 方法二：Dev Tools 查询

```json
GET wazuh-alerts-*/_search
{
  "size": 1,
  "sort": [{"timestamp": "desc"}],
  "query": {
    "bool": {
      "filter": [
        {"term": {"rule.id": "RULE_ID_HERE"}}
      ]
    }
  }
}
```

### 常见字段对照

| 含义 | 字段路径 | 示例值 |
|------|----------|--------|
| 规则 ID | `rule.id` | `100301` |
| 规则级别 | `rule.level` | `13` |
| 规则描述 | `rule.description` | `[TA0004-R01] Domain Admin Group Changed` |
| Windows Event ID | `data.win.eventdata.eventID` | `4728` |
| 操作用户 | `data.win.eventdata.SubjectUserName` | `admin` |
| 目标用户/组 | `data.win.eventdata.TargetUserName` | `Domain Admins` |
| 来源主机 | `agent.name` | `DC01` |
| 告警时间 | `timestamp` | `2026-09-16T09:00:00Z` |
| MITRE 战术 | `rule.mitre.tactic` | `TA0004` |
| MITRE 技术 | `rule.mitre.technique` | `T1098` |

---

## 三、Visual Editor 创建步骤（推荐简单场景）

### Step 1：进入创建页面

Wazuh Dashboard → **Explore** → **Alerting** → **Create monitor**

### Step 2：填写 Monitor 基本信息

| 字段 | 值 |
|------|-----|
| **Monitor name** | `[编号-序号] 规则名称` |
| **Monitor type** | `Per query monitor` |
| **Monitor defining method** | `Visual editor` |
| **Index** | `wazuh-alerts-*` |
| **Time field** | `timestamp` |
| **Schedule** | `By interval` |
| **Run every** | `1` `Minutes` |

### Step 3：配置查询条件（Visual Editor 表单）

添加过滤条件，多个条件之间选 AND/OR 逻辑：

| 条件序号 | Field | Operator | Value |
|----------|-------|----------|-------|
| 1 | `data.win.eventdata.eventID` | `is one of` | `4728, 4729, 4732, 4733, 4756, 4757` |
| 2 | `data.win.eventdata.TargetUserName` | `is` | `Domain Admins` |

### Step 4：添加 Trigger

点击 **Add trigger**：

| 字段 | 值 |
|------|-----|
| **Trigger name** | `触发条件描述` |
| **Severity level** | `1`（Highest）~ `5`（Lowest） |
| **Trigger type** | `Per query monitor` |
| **Condition** | `IS ABOVE` `0` |

### Step 5：添加 Action

在 Trigger 内点击 **Add action**：

| 字段 | 值 |
|------|-----|
| **Action name** | `通知动作描述` |
| **Channel** | 选择已配置的通知通道 |
| **Message subject** | `告警标题` |
| **Message** | 告警正文（支持模板变量） |

**消息模板**（支持 Mustache 语法）：

```
[SECURITY ALERT] 告警名称

Monitor: {{ctx.monitor.name}}
Trigger: {{ctx.trigger.name}}
Severity: {{ctx.trigger.severity}}
Period: {{ctx.periodStart}} ~ {{ctx.periodEnd}}
Matched: {{ctx.results.0.hits.total.value}} events

Please investigate immediately.
```

### Step 6：创建

点击 **Create** 完成。

---

## 四、Extraction Query Editor 创建步骤（推荐复杂场景）

### Step 1~2：同 Visual Editor

### Step 3：编写查询语句

在 Extraction query editor 中输入 OpenSearch Query DSL：

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "terms": {
            "data.win.eventdata.eventID": ["4728", "4729", "4732", "4733", "4756", "4757"]
          }
        },
        {
          "term": {
            "data.win.eventdata.TargetUserName.keyword": "Domain Admins"
          }
        }
      ]
    }
  }
}
```

**查询编写规范**：

| 规范 | 说明 |
|------|------|
| 用 `filter` 而非 `must` | 不参与评分，走缓存，性能更好 |
| 用 `term` + `.keyword` | 精确匹配，避免 analyzer 分词干扰 |
| 用 `terms` 匹配多值 | 等价于 OR，比多个 `match_phrase` 更高效 |
| 用 `range` 匹配数值/时间 | 如 `rule.level >= 10` |

### Step 4~6：同 Visual Editor

---

## 五、两种方式对比

| | Visual Editor | Extraction Query Editor |
|--|--------------|------------------------|
| 适用场景 | 简单 AND/OR/IS 条件 | 复杂逻辑、聚合、脚本 |
| 学习成本 | 低 | 需要懂 Query DSL |
| 灵活性 | 受限于表单选项 | 完全自定义 |
| 可复用性 | 无法导出为代码 | 可版本化管理 |

---

## 六、模板变量速查

| 变量 | 含义 |
|------|------|
| `{{ctx.monitor.name}}` | Monitor 名称 |
| `{{ctx.trigger.name}}` | Trigger 名称 |
| `{{ctx.trigger.severity}}` | 严重级别 |
| `{{ctx.periodStart}}` | 查询起始时间 |
| `{{ctx.periodEnd}}` | 查询结束时间 |
| `{{ctx.results.0.hits.total.value}}` | 匹配文档数 |
| `{{ctx.results.0.hits.hits}}` | 匹配文档列表（可用 `#` 循环） |

**循环输出匹配详情**：

```
{{#ctx.results.0.hits.hits}}
- EventID: {{_source.data.win.eventdata.eventID}}
  User: {{_source.data.win.eventdata.SubjectUserName}}
  Time: {{_source.timestamp}}
{{/ctx.results.0.hits.hits}}
```

---

## 七、示例：Domain Admin Group Changed

### 背景

- **MITRE ATT&CK**：TA0004 Privilege Escalation / T1098 Account Manipulation
- **Wazuh Rule Chain**：184666 → 100300 (Event ID) → 100301 (Domain Admins)
- **触发条件**：Domain Admins 组成员被添加或移除

### Visual Editor 配置

| 字段 | 值 |
|------|-----|
| Monitor name | `[TA0004-R01] Domain Admin Group Changed` |
| Index | `wazuh-alerts-*` |
| Time field | `timestamp` |
| Schedule | Every 1 minute |
| Filter 1 | `data.win.eventdata.eventID` is one of `4728, 4729, 4732, 4733, 4756, 4757` |
| Filter 2 | `data.win.eventdata.TargetUserName` is `Domain Admins` |
| Trigger name | `Domain Admin Group Change Detected` |
| Severity | 1 (Highest) |
| Condition | IS ABOVE 0 |
| Action | Send to notification channel |

### Extraction Query Editor 配置

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "terms": {
            "data.win.eventdata.eventID": ["4728", "4729", "4732", "4733", "4756", "4757"]
          }
        },
        {
          "term": {
            "data.win.eventdata.TargetUserName.keyword": "Domain Admins"
          }
        }
      ]
    }
  }
}
```

---

## 八、部署后验证

### 1. 测试告警匹配

在 Dev Tools 中手动触发查询，确认能匹配到数据。

### 2. 发送测试通知

在 Action 配置中点击 **Send test message**，验证通知通道是否正常。

### 3. 监控 Monitor 状态

Alerting → Monitors → 查看 Monitor 的 **State** 和最近执行结果。

---

## 九、最佳实践

1. **先查再写**：用 Dev Tools 确认字段结构后再写 query
2. **用 filter 不用 must**：所有精确匹配条件用 `filter` 上下文
3. **keyword 字段做精确匹配**：字符串字段加 `.keyword` 后缀
4. **合理设置频率**：高优先级 1 分钟，低优先级 5-15 分钟
5. **消息模板要含关键信息**：事件时间、来源主机、操作用户、匹配数量
6. **版本化管理**：将 query 和配置记录到 Git 仓库

---

## 十、Wazuh 常见安全监控规则 ID 速查

| Event ID | 含义 | MITRE |
|----------|------|-------|
| 4720 | 用户账户创建 | T1136 |
| 4722 | 用户账户启用 | T1136 |
| 4724 | 密码重置 | T1098 |
| 4725 | 用户账户禁用 | T1531 |
| 4726 | 用户账户删除 | T1531 |
| 4728 | 成员添加到全局安全组 | T1098 |
| 4729 | 成员从全局安全组移除 | T1098 |
| 4732 | 成员添加到本地安全组 | T1098 |
| 4733 | 成员从本地安全组移除 | T1098 |
| 4735 | 安全组已更改 | T1098 |
| 4737 | 安全组已更改 | T1098 |
| 4738 | 用户账户已更改 | T1098 |
| 4740 | 用户账户被锁定 | T1110 |
| 4756 | 成员添加到通用安全组 | T1098 |
| 4757 | 成员从通用安全组移除 | T1098 |
| 4767 | 用户账户已解锁 | T1098 |
| 4625 | 登录失败 | T1110 |
| 4648 | 使用显式凭据登录 | T1078 |
| 4672 | 特殊权限分配 | T1078 |
| 4688 | 新进程创建 | T1059 |
| 4697 | 服务已安装 | T1543 |
| 4698 | 计划任务已创建 | T1053 |
| 7045 | 新服务安装 | T1543 |
