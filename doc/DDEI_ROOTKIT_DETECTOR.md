# DDEI Rootkit 专用检测器

本分支在原 DFIR 采集之前运行 DDEI 专用检测。范围是案例中的用户态预加载、PAM 认证链和伪装服务行为，不是通用内核 rootkit 扫描器。

## 使用和输出

```sh
# 仅检测
sudo ./ddei-rootkit-detector-linux-amd64 -detect-only
# 默认检测、六模块采集、双输出、自动打包
sudo ./ddei-rootkit-detector-linux-amd64
# 可选显式超时和日志位置
sudo ./ddei-rootkit-detector-linux-amd64 -detect-only -timeout 2m -detector-log-dir ./logs
```

ARM64 使用对应 arm64 文件。需要 root 和可读的 /proc；读取不足不能作完整 CLEAN 结论。

| 查看内容 | 位置 |
|---|---|
| 判定、依据、覆盖和执行状态 | 控制台；具体执行错误在标准错误 |
| 专用人读日志 | 二进制目录 ddei_rootkit_check_YYYYMMDDThhmmssZ.log，中文，0600 权限，同秒自动换名 |
| 包内人读检测报告 | dfir_*/legacy/ddei_rootkit/report.txt |
| 包内检测 JSON | dfir_*/legacy/ddei_rootkit/report.json |
| 原有人读采集 | dfir_*/legacy/ |
| AI 采集事实 | dfir_*/ai/evidence.jsonl，单文件，不含检测 verdict |
| 索引及完整性 | ai/manifest.json、ai/artifact_index.json |
| 最终压缩包 | 运行时当前目录 dfir_年月日时分秒.tar.gz |

检测日志用 UTC；采集目录时间用主机本地时区。二进制目录和工作目录可以不同。仅检测不创建采集目录或压缩包。

默认 ddei profile 为 host/system/process/network/persistence/logs 六模块，不是 deep。仅默认 profiles/ddei.yaml 缺失才内置兜底；显式错误目录、损坏配置和权限错误会失败。其他 profile 仍需配置文件。detect-only 与 no-detect 互斥。

## 判定契约

| 状态 | DDEI 退出码 | 含义 |
|---|---|---|
| CLEAN | 0 | 请求的检查完整，无感染规则或未解决异常；仅限本次规则及观察时刻 |
| INFECTED | 3 | 精确感染证据或完整行为组合命中，报告列出依据 |
| INCONCLUSIVE | 2 | 覆盖不足、读取/解析失败、取消或证据不足；不能判白 |
| 执行失败 | 2 | 日志无法保存、配置错误或后续采集失败；与检测结论分开显示 |

no-detect 的普通采集错误保留原退出码 1。检测阳性可以与 complete=false 并存：已有感染证据不会被其他缺口抹掉，但不足的覆盖仍必须报告。

**hash/IP 没命中不能单独产生 CLEAN**，行为与覆盖检查照常继续。不存在对所有样本、所有主机保证零误报和零漏报的有限规则；不足时保留 INCONCLUSIVE。

## 精确证据路径

- 已确认九月样本 SHA256 可直接精确匹配。MD5 单独命中需 SHA256 复核。
- 八月包中的 loader/PAM/xinetd 哈希属于案例相关指纹：活动 loader 加上活动 PAM 或运行中的对应程序形成组合。不是按同名文件定性。
- 本次指定两个 IP：101.91.168.5、14.116.197.139。只有实际 socket 的远端命中、活动状态且关联进程才定性；文本出现、本地监听地址不触发。
- 残留/无 owner 连接保留为待核查。网络通过 /proc 读取，不主动连接这些地址，不联网查询。
- 没有命中精确指标时仍执行全部行为判断。

## 通用行为路径

规则 A 必须同时具备：

1. 配置中的 preload 对象经有效 ELF 检查，且确实映射在活跃进程中；以实际文件对象身份关联。
2. 同一 PAM auth 配置、同一个有效 ELF 模块，包含两种案例认证控制：[success=1 default=ignore] 和 [success=done default=ignore]。
3. 同一个 root、PPID=1 进程同时存在 RWX 映射和 PTY 文件描述符，不要求程序名为 xinetd。

规则 B 必须同时具备：

1. 有效 preload 对象被配置并实际映射。
2. ELF 定义至少五个不同的拦截符号，跨至少三类文件操作（目录枚举、元数据、访问、删除），导入符号不算。
3. root、PPID=1 的同一个进程同时具有 RWX 与 PTY。

规则不依赖固定 hash、IP、libnet/pam_ssh 文件名。任一完整关联可触发 INFECTED，报告保留配置、对象和 PID 依据。这是针对案例的高特异性组合，不是任意 rootkit 的完备识别算法。

以下不能单独判感染：文件名、两个 hook 符号、RWX/JIT、静态或大体积 xinetd、标记目录、64-hex 文本、普通 SMTP 外联、DDEI cgroup、mtime/ctime 差异、包归属缺失。正常系统的 unattended-upgr 也能出现 RWX；不按进程名称豁免，按证据组合判断。

## 执行及兼容边界

- 检测器不加载/执行被检查 ELF，不改 PAM/preload，不清理，不杀进程。
- 有界文件读取和 ELF 预验证；畸形输入返回检查缺口，不能 panic 或静默当作文件不存在。
- 区分权限拒绝、文件缺失、进程退出和 PID 生命周期变化。映射关联绑定实际读取对象。
- 显式 timeout 对检测和后续采集传递 context；归档沿用通用实现，不宣称严格端到端硬时限。未指定时不启用总超时；profile 历史 10m 字段不是自动上限。
- 默认完整采集仍继承原采集器的部分外部命令观察。本轮仅修 DDEI 引入的问题，未修改通用模块。静态检测器不能保证动态子程序同样可信。
- 日志解析上限等通用采集限制仍在 AI errors 流；归档成功不意味着采集无缺口。
- 固定大小、时间、规则数量不能证明所有变种已覆盖；被修改内核也不在本工具可信性保证之内。

## 证据及测试

八月原始包及 evidence.jsonl 已按归档 SHA256 和 manifest 核验。规则依据包括：
loader E13985、PAM E14135/E14136、活跃映射 E1118、RWX/PTY/UID/PPID E1075、进程指纹 E1577、实际连接 E2587。

tests/ddei/testdata/case-20260825.json 仅保存这些记录的最小字段投影，不含客户凭据、主机标识或恶意二进制。原始包不含 ELF 原件，因此：
- 完整历史证据可验证精确/组合规则；
- 去掉 hash/IP 后，历史投影缺少 ELF 原件验证，必须保留 INCONCLUSIVE，不能补假字段制造阳性；
- 无固定 IOC 的完整行为路径使用实际解析的安全合成 ELF 和隔离 /proc fixture 验证，不能称为真实样本执行测试。

```sh
go test -race ./internal/detector/ddeirootkit ./internal/app ./tests/ddei
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ddei-rootkit-detector-linux-amd64 ./cmd/dfir-collector
```

验收包括正常基线、案例回放、变更 hash/IP 的合成行为阳性、移除组合条件的反例、损坏 ELF、权限/超时、进程竞态、网络本地/远端区分。Ubuntu ARM64 验证不能代替实际 DDEI/CentOS x86_64 验证。
