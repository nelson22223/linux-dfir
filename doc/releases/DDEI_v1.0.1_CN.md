# DDEI Rootkit Detector v1.0.1（Linux x86_64）

本版本为 DDEI 专用检测及应急采集工具，不是通用病毒扫描器。架构为 Linux x86_64 / amd64，不支持 32 位 x86。

## 使用

下载 tar.gz 包并解压，在解压目录执行：

```sh
sha256sum -c SHA256SUMS
chmod +x ddei-rootkit-detector-linux-amd64
# 默认：检测、六模块采集、人读/AI 双输出、压缩打包
sudo ./ddei-rootkit-detector-linux-amd64
# 仅检测
sudo ./ddei-rootkit-detector-linux-amd64 -detect-only
```

默认缺少 profiles/ddei.yaml 时使用内置 DDEI 配置，无需安装 Go、额外依赖或联网。默认不启用病毒扫描、清理或总超时。

## 结果位置

- 控制台：判定、覆盖情况、最终执行状态和产物路径。
- 二进制目录：ddei_rootkit_check_时间.log 专用人读日志。
- 当前工作目录：dfir_年月日时分秒.tar.gz，以及对应采集目录。
- 包内 legacy/ddei_rootkit/report.txt：人读检测报告；report.json：机器可读检测报告。
- 包内 legacy/：原有人读采集；ai/evidence.jsonl：单一 AI 采集事实流。
- 仅检测模式不产生采集目录和压缩包。

退出码：0=CLEAN；3=INFECTED；2=INCONCLUSIVE 或 DDEI 执行失败。显式 no-detect 的普通采集错误保留退出码 1。执行失败与检测结论分别呈现。

## 本次更新

- 修复 ELF 畸形数据及可变文件读取风险；哈希、预检和解析使用同一有界快照。
- 补齐读取/解析失败、进程映像与映射变化、网络 namespace 变化的覆盖记录，避免错误判白。
- 使用确认的 hash/IP 和 preload/PAM/进程的组合行为；未命中 IOC 不作为判白依据。
- 取消仅凭文件名、大小、RWX 或少量 hook 符号判感染。
- 修复日志写入失败、互斥参数、配置回退、超时和退出码处理。
- 保留原有人读和 AI 输出，增加包内人读专用检测报告。

## 验证与限制

- 独立代码 review、定向 race 测试通过；UTM Ubuntu ARM64 全量测试通过。
- 正常 VM 检测约 0.47 秒；默认检测、采集和打包约 13.8 秒，耗时不代表实际 DDEI 设备。
- 案例证据回放及安全合成行为用例检出；缺失条件、畸形 ELF 等不被错误判白。
- 此 x86_64 产物为静态交叉编译，尚未在实际 DDEI/CentOS x86_64 上执行验证。
- 原始归档无 ELF 原件，未执行真实恶意样本。不保证所有变种零误报、零漏报；覆盖不足使用 INCONCLUSIVE。
- 通用采集器的外部命令依赖和日志解析上限未在本轮修改。AI error_event 必须一并查看；打包成功不表示全部日志无截断。
- 运行会写入日志及采集产物，读取可能影响访问时间；不清理、不杀进程、不加载被检查 ELF。

详细规则见仓库 doc/DDEI_ROOTKIT_DETECTOR.md。
