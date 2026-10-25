# log-privacy

面向车端 JSONL 日志的离线隐私清洗器。它能按规则删除 VIN、GPS、用户标识，按车队密钥稳定伪名化，并对 CAN ID 和时间戳做可配置处理。

## 痛点

NHTSA 建议建立事件日志、快速检测和可追溯文档，但原始日志往往包含 VIN、位置和用户标识。工程团队需要在共享日志前降低隐私暴露，同时保留故障关联能力。

## 使用

    python redact.py examples/input.jsonl examples/output.jsonl --secret demo-key

## 许可证

MIT
