# DDEI Rootkit Detector v1.0.3

## 变更

- 默认仅执行快速检测，控制台显示结果，不创建日志、采集目录或压缩包。
- 显式 --collect 才执行检测、六模块采集、人读/AI 双输出和压缩打包。
- 显式 --detector-log-dir 才额外保存一份检测报告。
- 控制台、专用报告、检测规则说明和应用错误消息改为英文；原始证据内容保持原样，不翻译或改写。
- 提供 Linux amd64、arm64、386 三种静态二进制；不改变检测规则和退出码。

## 使用

按主机架构选择对应二进制。以下为 amd64 示例：

```sh
chmod +x ddei-rootkit-detector-linux-amd64
# 默认只检测，0 个工具文件
sudo ./ddei-rootkit-detector-linux-amd64
# 只检测，另外保存 1 个 .log
sudo ./ddei-rootkit-detector-linux-amd64 --detector-log-dir ./logs
# 检测、完整 DDEI 采集与压缩
sudo ./ddei-rootkit-detector-linux-amd64 --collect
```

三架构合集解压后执行 `sha256sum -c SHA256SUMS`。没有自动架构选择启动器，需要选择对应文件。

## 每次产物

| 参数 | 工具创建的产物 |
|---|---|
| 无参数 / --detect-only | 无文件，仅控制台 |
| --detector-log-dir ./logs | 1 个检测 .log，必要时创建指定目录 |
| --collect | 1 个 dfir_年月日时分秒目录 + 1 个同名 tar.gz，无独立检测 .log |
| --collect --detector-log-dir ./logs | 上述目录和压缩包 + 1 个独立 .log |

采集目录内含 legacy/、ai/evidence.jsonl 和索引等；legacy/ddei_rootkit/report.txt 为英文人读检测报告。内部文件数量随主机内容变化。历史日志不覆盖、不自动删除；系统自身的 sudo/audit 等日志可能记录运行。

## 英文回显示例（省略动态证据字段）

```text
Verdict: CLEAN
No family indicators found within the checked scope.
Execution: completed; detection=CLEAN; collection=not_started; exit_code=0
```

```text
Verdict: INFECTED
Evidence of infection found. Isolate the host and preserve evidence.
Execution: completed; detection=INFECTED; collection=not_started; exit_code=3
```

```text
Verdict: INCONCLUSIVE
Insufficient evidence for a conclusive result; further investigation required. Not CLEAN.
Execution: completed; detection=INCONCLUSIVE (incomplete coverage); collection=not_started; exit_code=2
```

仅因证据待核查、覆盖本身完整时，不显示 incomplete coverage。执行失败另行显示 failed，DDEI 退出码为 2。显式 --no-detect 保留原只采集行为及普通错误码 1；它不会保存检测报告。

## 验证边界

发布前检查三架构编译、定向回归与 Linux ARM64 VM 实际输出/文件数量。amd64 和 386 尚未在对应架构实机执行。有限规则不保证所有变种零误报/漏报；证据不足不判白。工具不自动隔离或清理主机。

完整规则见 doc/DDEI_ROOTKIT_DETECTOR.md。原通用采集器的外部命令依赖和日志解析上限未在本版重构。
