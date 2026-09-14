# DDEI Rootkit Detector v1.0.4

## 本次更新

- 默认控制台固定两行 Execution 和 Verdict，不创建工具文件。
- 新增 --verbose，打印完整英文检测报告，包括 INFO、REVIEW、命中依据和覆盖缺口；该参数本身不启用采集或日志文件。
- 修复 PAM 多架构共存解析：按实际 ELF 架构检查每个候选模块，同一文件的路径别名去重；不再把正常 32/64 位共存直接当成无法解析。
- 路径候选不等于实际加载，不能凭同名模块构造加载关联。同架构冲突、缺失、不可读和损坏仍保留检查缺口。
- 无进程或模块白名单。保留 hash/IP 及行为规则；未命中 IOC 不作为判白依据。
- 三种 Linux 静态二进制：amd64、arm64、386，使用同一源码提交构建。

## 使用

以下以 amd64 为例，按实际主机架构选择二进制：

```sh
chmod +x ddei-rootkit-detector-linux-amd64
# 默认：仅检测，固定两行，不产生文件
sudo ./ddei-rootkit-detector-linux-amd64
# 简单调试：完整检测输出，不产生文件
sudo ./ddei-rootkit-detector-linux-amd64 --verbose
# 仅检测，完整报告保存到一个文件
sudo ./ddei-rootkit-detector-linux-amd64 --detector-log-dir ./logs
# 检测、原有六模块采集、人读/AI 双输出与压缩
sudo ./ddei-rootkit-detector-linux-amd64 --collect
```

--verbose 可与 --collect 或 --detector-log-dir 组合。没有自动架构选择启动器。三架构合集解压后可执行 `sha256sum -c SHA256SUMS` 校验。

## 两行结果

```text
Execution: SUCCESS
Verdict: CLEAN
```

- Execution 为 SUCCESS 或 FAILED，表示本次检测及显式采集是否完成，不表示主机是否感染。
- Verdict 为 CLEAN、INFECTED 或 INCONCLUSIVE。
- 有感染证据但其他检查失败时，可出现 FAILED + INFECTED，感染证据不会被覆盖缺口抹掉。
- INCONCLUSIVE 不是 CLEAN；完整执行但证据仍待核查时，也可能 SUCCESS + INCONCLUSIVE。
- DDEI 退出码仍为 0（CLEAN）、3（INFECTED）、2（不充分或执行失败）。兼容 --no-detect 保留原只采集行为，--help 保留帮助。

## 文件数量

| 参数 | 每次新增工具产物 |
|---|---|
| 无参数 / --verbose / --detect-only | 0 个文件 |
| --detector-log-dir ./logs | 1 个完整检测 .log，必要时创建目录 |
| --collect | 1 个 dfir_年月日时分秒目录 + 1 个 tar.gz，不另建检测 .log |
| --collect --detector-log-dir ./logs | 上述目录和压缩包 + 1 个独立 .log |

采集目录含 legacy/、ai/evidence.jsonl 和索引等，内部文件数量随主机变化。保存的检测报告仍含完整英文依据；原始证据不翻译。旧文件不自动删除，系统自身 sudo/audit 日志可能记录运行。

## 验证与限制

发布前验证三架构构建、独立 review/测试、Ubuntu ARM64 VM，以及安全合成的双架构 PAM 文件系统场景。未在用户实际 DDEI x86_64 主机上执行修复版；amd64、386 尚无对应实机运行验证。修复这类 PAM 缺口不保证所有主机都 CLEAN，其他缺口仍可能导致 INCONCLUSIVE。

不加载被检查模块，不运行恶意样本，不自动清理或隔离主机。不保证所有变种零误报/漏报。通用采集器外部命令依赖和日志解析上限未在本版重构。
