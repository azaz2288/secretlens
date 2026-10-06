# SecretLens

离线 Git 密钥门禁：检查**真正暂存的字节**，而不是工作目录里你以为会提交的版本。JSON 报告只包含路径、规则、行列和指纹，不包含密钥或上下文片段，不联网验证密钥。

Python 3.12+ 和 Git，无运行时第三方包。

```sh
python -m secretlens --repo /path/to/repository
python -m unittest discover -s tests -v
python -m pip install .
secretlens --repo /path/to/repository
```

退出码：0 表示本次规则未发现候选；1 表示存在候选；2 表示覆盖不完整/操作失败。全部命令输出 ASCII-safe JSON。可把 `secretlens --repo .` 放进 Git pre-commit hook，失败时阻止提交；确保命令安装到 hook 的运行环境。默认扫描整个索引，包含未修改的已跟踪文件，不扫描未暂存/未跟踪文件、历史提交和远端。

## 已实现的首个纵向版本

- 从一个 NUL 分隔索引列表取得不可变 blob ID，正确处理空格、制表符、换行和 Unicode 路径。
- GitHub token、AWS access ID、私钥标记、引号中的长敏感字段赋值候选。
- UTF-8、带 BOM 的 UTF-16/UTF-32；二进制中的 ASCII-compatible token 也不被静默跳过。
- 默认单文件 1 MiB、全部索引 32 MiB、10,000 文件；超限、冲突、子模块、符号链接和 Git 错误均失败关闭。先检查所有大小，再读取内容，不把部分检查标为 clean。
- 默认扫描只读；不编辑源码、索引、Git 配置或历史。v0.4显式hook安装/卸载仅改变目标仓库 `.git/hooks/pre-commit`。

## 重要限制

这是 v0.5.1 的可用工程阶段，**不是全面密钥发现或完整安全保障**。不检测所有供应商、加密/压缩/转义后的密钥、无 BOM 的宽字符编码；短密码也可能漏报。占位符可能误报，只允许下述显式精确例外，不提供通配忽略。报告中的路径可能本身敏感；指纹是确定性 SHA256，不是加密，低熵值可能被字典猜测。Git 对象及本地 Git 可执行程序视为可信；大小和候选数量限制不是操作系统级资源沙箱。

扫描结果绑定获取索引列表时的 blob 集合；之后改动暂存内容必须重新运行。秘密进入 Git 历史后，删除文件不能撤销泄漏，仍须吊销/轮换凭据。不改写任何已有项目历史。

## v0.5.1 候选预算与密集输入

默认最多保留整个索引 **10,000 个候选出现**，不是10,000种不同值：重复文件按路径分别计数，同一位置触发两个规则也计两次。`--max-findings 20000` 可显式调整为正整数；不提供无限/零/负数开关。超出预算立即失败关闭，退出2且 `complete=false, clean=false`，不输出部分findings，不把截断列表当完整检查。审批在完整扫描后应用，因此不能通过审批绕过候选上限。

达到预算后仍检查剩余clean文件；一旦发现下一候选即失败。blob迭代器在失败时关闭，释放Git进程/管道。该预算限制保留结果数量，不保证总RSS、运行时间、JSON字节数或恶意正则CPU隔离；文件/总字节/文件数限额仍独立生效。Python `scan_blob(..., max_findings=0)` 仅允许clean blob，供索引内部用剩余预算继续检查，索引/CLI/hook要求正数。

行列定位现在按每条规则的递增匹配分段统计换行，不再对每个候选重扫全文前缀；位置、规则、指纹与排序不变。可复现的合成密集blob对照见[benchmarks/README.md](benchmarks/README.md)，不是实际仓库吞吐或普遍加速承诺。

## v0.2 受控精确例外

v0.3批量读取：非空索引用三个Git进程完成索引列表、全部对象大小预检和逐文件流式读取；不会先读内容再发现总量超限。验证header、类型、size、终止符与Git对象hash（SHA1/SHA256仓库均支持），禁用replace refs及缺失对象的惰性网络获取，拒绝截断或异常尾部。30秒批处理watchdog会终止卡住的Git子进程；这是进程/I/O截止，不是恶意输入的CPU/内存沙箱。仍按路径分别扫描，不缓存跨文件秘密。10,000文件实测见benchmarks/README.md。

只有显式传入 `--approvals trusted-policy.json` 才使用策略，不自动信任被检查仓库中的文件。格式：

```json
{
  "version": 1,
  "approvals": [{
    "path": "tests/synthetic-fixture.txt",
    "rule": "github-token",
    "fingerprint": "复制本次报告的64位小写SHA256",
    "reviewer": "负责审查的人员",
    "reason": "该值是经过审查的无效合成样例",
    "expires_at": "填写带时区的未来ISO8601时间，最多90天"
  }]
}
```

以上占位内容不是可用放行凭据。path/rule/fingerprint必须同时精确匹配，移动路径/改变token不继承放行；拒绝通配符、绝对/越界路径、重复条目、过期/无时区/超过90天策略、缺失审查说明；私钥候选永不允许放行。候选仍保留在 `findings` 中并附 `approved`/审查信息，`policy`报告未放行数和未使用审批数；启用策略后的`clean`指门禁是否通过，不代表没有候选。到期策略让命令返回2，不能静默延续例外。

reviewer只是审计元数据，没有身份认证/签名，不是多方审批服务。由CI维护者保护策略文件和传入参数，不能允许待审PR自己换策略或命令来放行。元数据中不要写实际密钥或敏感信息。

## v0.4 显式提交前门禁

先安装到独立环境，再明确选择要启用的仓库：

```sh
python -m venv .venv
# Windows:
.venv/Scripts/python.exe -m pip install .
.venv/Scripts/python.exe -I -m secretlens --repo /path/to/repository --install-hook
# macOS/Linux:
.venv/bin/python -m pip install .
.venv/bin/python -I -m secretlens --repo /path/to/repository --install-hook
```

也可用 `secretlens --repo /path/to/repository --install-hook --python /absolute/path/to/installed/python` 指定runtime。安装前用隔离模式确认该Python装有当前版本，源码目录直接启动并不等于该runtime已安装包。安装不扫描/改动索引，不修改Git配置，不自动在其他仓库启用。没有 `--force`：已有hook（含自己安装过的）一律保留并拒绝覆盖；先审阅/卸载再明确重装。

生成的hook使用绑定Python的 `-I -m secretlens`：不从待审工作目录、PYTHONPATH或PYTHONHOME导入同名模块。全索引规则检测、覆盖超限或runtime缺失时都阻止普通commit；Git自己的临时 `GIT_INDEX_FILE` 保留，部分提交扫描本次实际临时索引，而不是错扫另一个暂存集合。三个旧限额不变，新增10,000候选预算；安装时可显式设置四个 `--max-*` 参数，包括 `--max-findings`，新hook将预算写入绑定配置。审批只有安装时显式 `--approvals /trusted/policy.json` 才绑定，安装先验证格式/到期；commit时重新读取验证，过期或缺失阻止提交。不自动加载仓库审批文件。

升级runtime后，未显式绑定预算的原v0.4/v0.5 hook将采用新版默认10,000上限；密集仓库可能由以前候选退出1变为覆盖不完整退出2。旧hook没有被自动改写，原样生成的旧配置仍可安全卸载，再明确安装新配置。自定义/改动hook继续保留；不能仅更新源码就声称其他runtime也已升级。本轮不在用户已有仓库安装或重写hook。

仅支持具有本地 `.git` 目录的normal仓库根；bare、子模块、linked worktree/外部Git目录、`core.hooksPath` 配置、根/.git/hooks联接或符号链接都拒绝，避免改变共享/外部hook。需要自定义hook链时手工调用已安装隔离runtime的扫描命令，不静默替换原链。普通仓库日后新增worktree可能共享Git hooks，需自行审查作用范围。

```sh
secretlens --repo /path/to/repository --uninstall-hook
```

卸载只删除**原样生成**且身份/修改元数据未变化的本地hook；用户改过的脚本、普通自定义hook或链接不删除。不是签名身份或抵抗本机恶意改写的沙箱。卸载后不自动阻止commit；不改索引、历史、配置、其他hook或runtime。路径失效时普通提交失败，可明确卸载/修复环境，不回退到未验证扫描。

Hook是本机防误提交工具：`--no-verify`、其他软件改写hook、恶意本机权限、检查期间并发暂存仍可绕过，必须在受保护CI上另跑扫描。绑定解释器不意味着锁定以后安装的包字节。报告/配置内只有路径、规则/指纹和runtime元数据，不回显密钥；仍需保护这些元数据。当前没有增量扫描或index锁定到提交的原子保证。

真实临时Git测试覆盖clean commit、暂存secret但工作树已清理、影子Python模块、部分提交、缺runtime/超限拒绝、显式审批、已有hook/修改hook保护、并发安装和卸载。本轮不在用户现有14仓库安装hook。

独立安装后演示：用该runtime执行 `python -I examples/hook_demo.py`，整个过程只在临时合成Git仓库里操作，展示通过/阻止/卸载，不触碰个人仓库。这里的python须替换为已安装环境的Python路径。

## v0.5 可重现规则评测

```sh
python -m secretlens.evaluation --check
# 安装后的等价入口：
secretlens-evaluate --check
```

离线生成647个原创合成样本，不读取仓库/工作区文件、不联网、不调用模型、不验证供应商密钥。625个支持集覆盖4条规则、边界长度、UTF8/BOM与UTF16/32双端编码、Unicode行列、ASCII二进制、重复/重叠候选；独立预标注规则/行列，而非用scanner生成答案。22个known-gap样本刻意包含无BOM宽编码、转义JSON、短密码漏报与已知占位符误报。完整方法/当前计数见[evaluation/README.md](evaluation/README.md)。

输出分supported、known-gap和**包含全部样本**的overall逐规则TP/FP/FN/TN、precision/recall；计数单位为每规则/每样本“是否出现”，另严格核对全部定位和重复次数。没有正例或预测时相应比例为null，不伪造100%。报告绑定corpus bytes+真值和规则hash，只含计数/安全样本ID，不含candidate、上下文、逐样本内容hash或fingerprint。顺序改变不影响输出。

--check只以支持集定位/数量是否回归决定0/1，known-gap仍完整展示并计入overall；scanner异常/非法元数据返回2，不能算TN。支持集通过不代表没有known-gap，也不代表真实项目准确率。本轮没有增加/降低扫描规则来制造漂亮分数。

## 后续工程路线（未完成）

1. 受控精确例外、审批/过期机制，禁止泛化忽略整个目录。
2. 在已实现显式hook安装/卸载基础上补环境迁移和经过证明的增量扫描；不能静默减少覆盖。
3. 扩展供应商规则，使用合成语料评测误报/漏报。
4. 多编码和大型仓库压力/性能评测，优化批量 blob 读取。
5. 兼容性版本、依赖供应链审查与正式发布。

这是新作品集工程，不宣称符合飞书活动的原有私有仓库准入。
