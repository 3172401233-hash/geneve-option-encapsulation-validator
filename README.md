# geneve-option-encapsulation-validator
校验 Geneve TLV 选项、封装边界和转发表行为

## 说明

本工具**不生成真实 Geneve 报文**，也不发送任何网络流量。它只在内存中解析
Geneve TLV 选项字节流，并根据节点能力、转发表和 MTU 预算**模拟**逐跳转发
判定，用于定位"隧道静默丢包"类问题（例如一方支持、一方不支持新引入的
critical TLV 选项）。

兼容 Python 3.8.2+，仅使用标准库。

## 功能

- 解析 Geneve 选项（class / type / critical 位 / 4 字节对齐长度），检测
  选项长度越界和头部截断
- 未知 critical 选项：当前节点不支持则拒绝（drop），并记入
  `unsafe_options`（不能安全忽略的选项）
- 未知非 critical 选项：忽略转发，但在每一跳输出的 `ignored_options`
  中保留可见
- 重复 TLV（同一 class+type 出现多次）直接拒绝
- VNI 冲突：节点未服务于报文 VNI 时丢弃
- MTU 校验：内层报文 + IPv4/UDP/Geneve 基础头 + 选项开销超过 MTU 时丢弃
- 多路径：转发表可按选项内容（class, type）钉选不同下一跳
- 回程一致性：`check_roundtrip` 比对去程与回程的 critical 选项集合

## 输出

`validate_packet` 返回 `ValidationResult`：

- `hops`：每跳的解析结果（节点、动作 forward/deliver/drop、原因、
  被忽略的选项、被拒绝的选项）
- `terminal_node`：报文终止（送达或被丢弃）的节点
- `unsafe_options`：导致丢弃、不能安全忽略的选项列表
- `delivered` / `error`：最终状态

## 运行测试

```
python -m unittest
```

覆盖：critical 未知项拒绝、非 critical 未知项保留、重复 TLV、
长度损坏、多路径选路、MTU 边界、VNI 冲突、回程选项不一致。

## 最小示例

```python
from geneve_validator import (
    ForwardingTable, GeneveOption, Node, Route, validate_packet,
)

nodes = {
    "a": Node("a", capabilities={(0x0100, 1)}, vnis={100}),
    "b": Node("b", capabilities=set(), vnis={100}),
}
ftable = ForwardingTable([Route("a", 100, "b", "b")])
critical_opt = GeneveOption(0x0100, 1, critical=True, payload=b"\x00" * 4)

result = validate_packet(100, "a", "b", [critical_opt], nodes, ftable,
                         mtu=1500, inner_size=1400)
for hop in result.hops:
    print(hop.node, hop.action, hop.reason)
print("terminal:", result.terminal_node, "unsafe:", result.unsafe_options)
```
