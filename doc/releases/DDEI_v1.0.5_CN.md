# DDEI Rootkit Detector v1.0.5

## 更新

- PAM 配置引用的模块在搜索位置不存在时，按模块合并为 INFO，保留配置来源与控制条件，不单独导致 FAILED/INCONCLUSIVE。不可读、损坏、断链、候选歧义仍保留检查缺口；不按模块名加白。
- 修复经核实的 `/dev/zero (deleted)` 匿名共享映射被当作磁盘 ELF 检查的问题。通过本机内核 shmem 设备校准、map_files 链接及进程映射稳定性检查分类；保留 RWX 和感染关联检测。
- 详细模式按进程汇总共享映射；结构化报告保留映射地址、权限和身份信息。匿名共享分类不是内容安全结论。
- 默认仍只输出两行，不创建日志或采集文件。提供 amd64、arm64、386 三种静态 Linux 二进制。

## 使用

```sh
chmod +x ddei-rootkit-detector-linux-amd64
sudo ./ddei-rootkit-detector-linux-amd64
# 详细调试输出，不创建文件
sudo ./ddei-rootkit-detector-linux-amd64 --verbose
# 保存一个完整检测日志
sudo ./ddei-rootkit-detector-linux-amd64 --detector-log-dir ./logs
# 显式启用原有采集、AI/人读输出及压缩包
sudo ./ddei-rootkit-detector-linux-amd64 --collect
```

按主机架构替换二进制名；无自动架构选择启动器。合集解压后可使用 `sha256sum -c SHA256SUMS` 校验。

默认输出示例：

```text
Execution: SUCCESS
Verdict: CLEAN
```

Execution 为 SUCCESS/FAILED；Verdict 为 CLEAN/INFECTED/INCONCLUSIVE。感染证据不会因其他检查失败而被抹掉，因此 FAILED + INFECTED 是有效组合。退出码为 0（CLEAN）、3（INFECTED）、2（不充分或执行失败）。CLEAN 仅指本检测器范围，不保证主机整体安全。

## 产物

- 无参数、--verbose、--detect-only：不创建工具文件。
- --detector-log-dir：一个独立完整检测日志。
- --collect：一个时间戳采集目录及一个 tar.gz；含 legacy/、ai/evidence.jsonl 和索引，不另建独立检测日志。
- --collect 与 --detector-log-dir 可组合；旧文件不自动删除。

## 验证和限制

Ubuntu ARM64 UTM 全量 Go 测试通过，包含真实匿名共享可执行映射的分类和采集链路；VM 默认运行返回 SUCCESS/CLEAN。完成独立代码 review、定向测试和三架构交叉构建。amd64/386 尚未实机验证，用户实际 DDEI 主机尚未复测本版。

map_files 权限限制、内核差异或校准失败会回落原检查流程，仍可能 INCONCLUSIVE；不通过隐藏未知缺口强行判白。没有新增内存代码扫描能力，不保证零误报/漏报。不加载被检查模块、不自动清理或隔离，不修改其他进程内存。内核校准仅在检测器自身短暂建立并解除 4KB 不可执行映射。操作系统自身可能记录 sudo/audit 等运行日志。
