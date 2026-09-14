# DDEI Rootkit 专用检测器

本分支默认仅运行 DDEI 专用检测，控制台固定显示两行：Execution: SUCCESS/FAILED 和 Verdict: CLEAN/INFECTED/INCONCLUSIVE，不创建文件。不展开 INFO、REVIEW、命中详情或其他摘要。专用检测日志和报告仍保留完整英文依据；原始证据不翻译。显式 --collect 才启动原 DFIR 采集。范围是案例中的用户态预加载、PAM 认证链和伪装服务行为，不是通用内核 rootkit 扫描器。

## 使用和输出

```sh
# 默认仅检测，零工具输出文件
sudo ./ddei-rootkit-detector-linux-amd64
# 检测、六模块采集、双输出、自动打包
sudo ./ddei-rootkit-detector-linux-amd64 --collect
# 仅检测并额外保存一份人读报告
sudo ./ddei-rootkit-detector-linux-amd64 --detector-log-dir ./logs
# 完整英文检测回显，含 INFO/REVIEW，不创建文件
sudo ./ddei-rootkit-detector-linux-amd64 --verbose
```

ARM64 使用对应 arm64 文件。需要 root 和可读的 /proc；读取不足不能作完整 CLEAN 结论。

| 查看内容 | 位置 |
|---|---|
| 执行状态与判定 | DDEI 控制台固定两行 Execution 和 Verdict |
| 完整依据与覆盖 | 显式保存的检测日志或采集包内报告；执行失败必须显示 FAILED 并返回非零退出码 |
| 专用人读日志（仅显式指定非空 --detector-log-dir） | 指定目录 ddei_rootkit_check_YYYYMMDDThhmmssZ.log，英文，0600 权限，同秒自动换名 |
| 包内人读检测报告 | dfir_*/legacy/ddei_rootkit/report.txt |
| 包内检测 JSON | dfir_*/legacy/ddei_rootkit/report.json |
| 原有人读采集 | dfir_*/legacy/ |
| AI 采集事实 | dfir_*/ai/evidence.jsonl，单文件，不含检测 verdict |
| 索引及完整性 | ai/manifest.json、ai/artifact_index.json |
| 最终压缩包 | 运行时当前目录 dfir_年月日时分秒.tar.gz |

包内文件仅在 --collect（或兼容的 --no-detect 采集）时产生；跳过检测不生成检测报告。检测日志用 UTC；采集目录时间用主机本地时区。

| 调用 | 每次新增工具产物 |
|---|---|
| 无参数，或 --detect-only | 0 个文件，只有控制台输出 |
| --verbose | 0 个文件，展开完整检测报告及最终结果 |
| --detector-log-dir ./logs | 1 个检测 .log；首次可能创建 logs 目录 |
| --collect | 1 个采集目录（内含 AI、人读及索引等多个文件）+ 1 个 .tar.gz；无独立检测 .log |
| --collect --detector-log-dir ./logs | 上述采集目录和压缩包 + 1 个独立 .log |

重复默认运行不累积文件。--detector-log-dir 和 --collect 模式控制台也固定两行，保存的文件仍包含完整详情。兼容的 --no-detect 保留原只采集输出；--help 仍显示帮助。显式保存日志每次保留新文件，不覆盖旧证据，也不自动删除历史文件；显式采集保留目录和压缩包两份形态。采集内部文件数量随主机内容变化，不能固定为几个。操作系统自己的 sudo/audit 等日志仍可能记录工具运行，不属于工具主动生成文件。

Execution 表示本次检测/显式采集是否完成，不等同主机是否感染。覆盖不足或执行失败显示 FAILED；完整执行即使发现感染也可以显示 SUCCESS。感染证据不会因为其他检查缺口消失，因此 FAILED + INFECTED 是有效组合。INCONCLUSIVE 不能当作 CLEAN。

--verbose 是显式调试开关，会恢复 INFO、REVIEW、命中详情和覆盖提示；不改变检测规则、退出码或默认文件数量。默认模式仍固定两行。

PAM 相对模块名按实际 ELF 位数、机器类型和字节序区分候选，同一文件别名去重。正常 32/64 位共存不再直接报错；同架构歧义、不可读、断链或损坏仍记录缺口。配置引用的模块在搜索位置不存在时，记录为 INFO 配置事实，按模块合并并保留所有配置来源、auth/-auth 类型及控制条件，不单独导致执行失败或 INCONCLUSIVE。这不证明配置未启用，也不证明整个主机安全。候选文件不等于已加载模块，加载关联仍需进程映射及文件身份依据。不按进程名或模块名加入白名单。已有哈希及组合检测规则保持不变；默认两行输出不变，详细提示在 --verbose 或显式报告中查看。

--collect 默认 ddei profile 为 host/system/process/network/persistence/logs 六模块，不是 deep。默认检测模式不读取 profile。采集模式中仅默认 profiles/ddei.yaml 缺失才内置兜底；显式错误目录、损坏配置和权限错误会失败。其他 profile 仍需配置文件。detect-only 与 collect/no-detect 互斥；no-detect 显式保留只采集的兼容行为。扫描和清理参数必须显式启用采集，不能在默认检测模式中静默忽略。

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

### 匿名共享映射分类

Linux 上对 `/dev/zero (deleted)` 共享映射进行内核类型校验：在检测器自身临时建立 4KB 不可执行的匿名共享映射，读取其内部 shmem 设备号后立即解除映射；目标映射必须具有相同设备号、非零 inode、共享权限及精确匹配的当前 `map_files` 链接，并通过已有的进程身份与映射前后稳定性检查。不是按路径或固定设备号加白，不写磁盘文件，不修改其他进程内存。

确认后记录为 `shared_anonymous`，不再把它作为磁盘 ELF 文件读取。原 RWX 关联规则继续执行；`--verbose` 每个进程汇总一条，结构化报告 `shared_memory` 保留地址、权限、设备号和 inode。该分类不是内存内容安全结论，也不增加内存代码扫描能力。无法校验时回落原检查路径，权限错误等仍可能导致 INCONCLUSIVE。旧内核或安全策略限制 `map_files` 时不能保证消除原缺口。默认仍为两行，不自动生成文件。

以下不能单独判感染：文件名、两个 hook 符号、RWX/JIT、静态或大体积 xinetd、标记目录、64-hex 文本、普通 SMTP 外联、DDEI cgroup、mtime/ctime 差异、包归属缺失。正常系统的 unattended-upgr 也能出现 RWX；不按进程名称豁免，按证据组合判断。

## 执行及兼容边界

- 检测器不加载/执行被检查 ELF，不改 PAM/preload，不清理，不杀进程。
- 有界文件读取和 ELF 预验证；畸形输入返回检查缺口，不能 panic 或静默当作文件不存在。
- 区分权限拒绝、文件缺失、进程退出和 PID 生命周期变化。映射关联绑定实际读取对象。
- 显式 timeout 对检测和后续采集传递 context；归档沿用通用实现，不宣称严格端到端硬时限。未指定时不启用总超时；profile 历史 10m 字段不是自动上限。
- 显式完整采集仍继承原采集器的部分外部命令观察。本轮仅修 DDEI 引入的问题，未修改通用模块。静态检测器不能保证动态子程序同样可信。
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
