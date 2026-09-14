# DDEI Rootkit Detector v1.0.2（三架构）

与完整版一致，提供三种 Linux 静态二进制：

| 架构 | 文件 |
|---|---|
| x86_64 / amd64（64 位 Intel、AMD） | ddei-rootkit-detector-linux-amd64 |
| aarch64 / arm64（64 位 ARM） | ddei-rootkit-detector-linux-arm64 |
| i386 / i686（32 位 x86） | ddei-rootkit-detector-linux-386 |

本版在 v1.0.1 基础上修复 Linux 32 位文件时间字段的类型兼容问题，不改变检测规则或默认采集模块。三种产物使用同一源码提交构建。完整版 scripts/package_release.sh 和 Makefile 的 linux 目标也采用这三种架构。

## 使用

下载对应二进制，或下载包含三种二进制的 ddei-rootkit-v1.0.2-linux-all.tar.gz。下例适用于 x86_64；其他架构替换文件名。

```sh
chmod +x ddei-rootkit-detector-linux-amd64
sudo ./ddei-rootkit-detector-linux-amd64
# 仅检测，不采集打包
sudo ./ddei-rootkit-detector-linux-amd64 -detect-only
```

完整压缩包解压后可用 `sha256sum -c SHA256SUMS` 校验。单独下载时校验所选文件对应的 SHA256SUMS 条目。

默认运行检测、六模块采集、AI/人读双输出及压缩；默认不启用病毒扫描或清理。默认配置缺失时使用内置 DDEI profile，无需安装 Go 或联网。

## 输出与退出码

- 控制台显示判定和最终执行状态；二进制目录生成 ddei_rootkit_check_时间.log。
- 当前工作目录生成 dfir_年月日时分秒.tar.gz 及对应目录。
- 包内 legacy/ddei_rootkit/report.txt 为专用人读报告，report.json 为检测结构化报告。
- legacy/ 为原有人读采集，ai/evidence.jsonl 为单一 AI 采集事实流。
- 退出码 0=CLEAN，3=INFECTED，2=INCONCLUSIVE/执行失败；no-detect 普通错误保留 1。
- IOC 未命中不能单独判白，仍检查组合行为与覆盖。证据不足保留 INCONCLUSIVE。

## 验证边界

三架构编译检查通过。Linux ARM64 VM 有运行验证；amd64 和 386 尚未在对应架构真实主机上执行验证。不能承诺所有变种零误报/漏报，不能以 ARM64 测试代替真实 DDEI 设备测试。

工具写入日志和采集产物，不清理、不杀进程、不执行被检查 ELF。通用采集器继承的外部命令和日志解析上限不在本次修复范围；需查看 AI error_event，不能把压缩完成等同全部日志完整。

完整检测规则见 doc/DDEI_ROOTKIT_DETECTOR.md，上一轮加固说明见 doc/releases/DDEI_v1.0.1_CN.md。
