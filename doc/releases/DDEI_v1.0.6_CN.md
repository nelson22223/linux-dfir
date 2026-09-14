# DDEI Rootkit Detector v1.0.6

## 更新

- 映射文件优先通过内核 map_files 入口读取。不同设备号/inode 视图须经真实 procfs、实时映射及句柄身份核实；普通路径仍严格校验，不按库名加白。
- 失败诊断保留各读取入口、双方身份及原因，同一进程同一对象的重复失败合并。
- ELF 支持大型 NOBITS 及无需消费的压缩节区，仍限制检测所需元数据及整体读取，不放宽恶意输入防护。
- 网络快照变化最多重试三轮，持续变化仍报告缺口。取消或后续扫描失败不会丢弃此前已验证的观察，也不会拼接未验证的 socket 归属。
- 保留 PAM 去噪、匿名共享映射分类、默认两行输出。提供 amd64、arm64、386 三种静态 Linux 二进制。

## 使用

根据 CPU 架构选择二进制；普通与信创 Linux 使用相同程序，无发行版白名单。

```sh
chmod +x ddei-rootkit-detector-linux-amd64
sudo ./ddei-rootkit-detector-linux-amd64
# 详细英文诊断，不创建文件
sudo ./ddei-rootkit-detector-linux-amd64 --verbose
# 保存完整检测日志
sudo ./ddei-rootkit-detector-linux-amd64 --detector-log-dir ./logs
# 显式采集：人读、AI JSONL 及压缩包
sudo ./ddei-rootkit-detector-linux-amd64 --collect
```

无参数或 --verbose 不创建工具文件；--detector-log-dir 创建一个检测日志；--collect 创建时间戳采集目录和 tar.gz。旧文件不自动删除。三架构合集解压后可运行 `sha256sum -c SHA256SUMS`。

## 两行状态

```text
Execution: SUCCESS
Verdict: CLEAN
```

- Execution 为 SUCCESS/FAILED，表示请求的检查及显式采集是否完成，不表示是否感染。
- Verdict 为 CLEAN/INFECTED/INCONCLUSIVE。
- FAILED + INFECTED：已命中感染判据，同时存在其他检查缺口。不能因执行不完整而抹掉已确认的命中。
- SUCCESS + INFECTED：检查完成且命中感染判据。
- SUCCESS + INCONCLUSIVE 也可能出现：检查完成，但观察仍需进一步核查。
- 默认检测退出码 0 为 CLEAN，3 为 INFECTED，2 为不充分或执行失败；完整模式另有采集失败情况。判断时同时保留两行状态，不能只看执行成功与否。

## 验证和限制

独立开发、review、测试完成，review 发现的网络边界问题已修复并复核。Ubuntu ARM64 UTM 全量测试通过；以 root 验证普通文件、OverlayFS、真实匿名共享映射及合成身份差异回退；最终验证产物连续三次默认返回 SUCCESS/CLEAN。ELF 兼容测试覆盖 32/64 位、两种字节序与恶意元数据；三种架构交叉构建通过。

实际信创主机及其 libdcf.so 尚未现场复测，amd64/386 未做对应架构实机测试。现代 OverlayFS 未复现日志中完全相同的身份差异，合成回退测试不等于已确认现场根因。接口权限限制、持续变化和真正无法核实的信息仍可能返回 INCONCLUSIVE。

本工具检查指定 DDEI 家族证据，不保证主机整体安全或所有变种零误报/漏报。不加载被检查模块、不自动清理或隔离、不修改其他进程内存。操作系统自身可能记录 sudo/audit 等运行日志。
