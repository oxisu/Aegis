# 前端选型评估：Tauri（外壳）还是 Vue（界面）

> 结论先说：**外壳选 Tauri v2，界面选 Vue 3 + Tailwind 3 + Headless UI**。
> 这两件事是**正交**的——"Vue + Tailwind"回答的是"界面用什么写"，
> "Tauri"回答的是"这个界面跑在什么壳里"。原问题把它们当成了二选一，
> 实际上可以、也应该两个都要。
>
> 本文所有结论都带本机实测，不是查资料背下来的。

---

## 0. 一句话结论

| 维度 | 选择 | 理由 |
|---|---|---|
| 界面 | **Vue 3 + TypeScript + Tailwind 3 + `@headlessui/vue` + `@heroicons/vue`** | 与既有项目（git-sync-hub → qzone-sync）同一套栈：设计令牌、组件类组织方式、主题机制可直接沿用 |
| 桌面外壳 | **Tauri v2** | 后端本就是 Rust，**能直接 `use aegis_ipc`**，协议不可能漂移；体积小、无 Node 运行时 |
| 通信方式 | 复用现有**命名管道**，GUI **不提权** | 不新增 localhost 端口，不新增攻击面 |
| 前端语言 | TypeScript | 与 `Status` 文本协议的字段对齐要有类型兜底 |

⚠ 这条**修正了 `design-spec.md` §16 与 §21 第 4 项**原先写的
"Tauri + React + Fluent UI v9"：界面那一层换成 Vue + Tailwind，
外壳（Tauri）保持不变。

### 0.1 为什么不用 Element Plus（2026-10-19 二次改定）

中途曾定过 Element Plus，落地脚手架时改掉了。两条理由，第二条是决定性的：

1. **视觉语言对不上**。既有项目用的是"设计令牌 + 原子类 + 少量组件类"
   （`--accent` 令牌、`bg-surface-hover/60` 这类原子类、`.surface-card`
   这种自研卡片类）。Element Plus 自带一套组件外观和 CSS 变量，
   两套并存的结果是"表格是 Element 的，卡片是自研的"，接缝处看得出来。
2. **⚠ 语义色会被绕开**。Aegis 有两组**不能写错**的语义色：绝缘等级
   （`lv-*`）和守卫状态（`guard-*`）。它们的危险程度由令牌统一定义，
   页面只能写 `text-guard-ineffective`。用 Element 的 `<el-tag type="danger">`
   这类组件就等于把颜色决策交给组件库——"未生效"和"判不了"一旦同色，
   人分不清"正在断网"和"只是能力缺口"。

   把 `lv-*` / `guard-*` 注册进 Tailwind 色板就是为了**让写错的写法不存在**：
   页面里写不出 `text-red-500`，只能从色板里挑。

---

## 1. 为什么必须先纠正一个旧结论

本机环境笔记里一直写着「**VS Build Tools 装不上**」（进程环境同时存在
`Path` 与 `PATH` 导致 .NET 抛 0x80070057）。**这条已经过时了**，据此
判断"Tauri 做不了"会得出错误结论。

实测（2026-10-19）：

```text
vswhere -all -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64
  → D:\vs-buildtools          ← 有实例，且带 VC 工具组件

D:\vs-buildtools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe    ✓
D:\vs-buildtools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe  ✓

cl.exe -nologo hw.c -Fe:hw.exe   →  编译 + 链接通过
./hw.exe                          →  msvc-ok
```

`C:\Program Files\Microsoft Visual Studio` 确实**不存在**——因为装在 D 盘。
之前只查了 C 盘就下了"没装"的结论。

---

## 2. 本机能力盘点（全部实测）

| 项 | 结果 | 怎么验的 |
|---|---|---|
| Node / npm | **v22.22.2 / 10.9.7** | `node -v` / `npm -v` |
| npm 源可达 | ✅ `registry.npmjs.org` | 实际装上的：vue 3.5.44、vue-router 4.6.4、pinia 3.0.4、tailwindcss 3.4.19、`@headlessui/vue` 1.7.23、`@heroicons/vue` 2.2.0 |
| MSVC 生成工具 | ✅ VC **14.44.35207**，`cl.exe`+`link.exe` 齐全 | `vswhere` + hello world 编译运行 |
| Windows SDK | ✅ **10.0.26100.0**（Include/Lib 全在） | `ls .../Windows Kits/10/{Include,Lib}` |
| WebView2 Runtime | ✅ **155.0.4283.62** 已装 | `ls .../Microsoft/EdgeWebView/Application` |
| Rust 工具链 | gnu（默认）+ **msvc 两个都在** | `rustup toolchain list` |
| msvc 编全项目 | ✅ **55s**，`aegisd` + 完整 `windows` 0.58 编过 | `cargo +stable-x86_64-pc-windows-msvc build -p aegisd` |
| rustc 自动找 MSVC | ✅ **不需要设 `INCLUDE`/`LIB`** | 清空环境后 `build -p aegisctl` 17.76s 通过 |
| Node 连命名管道 | ✅ 建连 + 回显通过 | 见 §3 |
| 浏览器连命名管道 | ❌ **不可能** | 见 §3 |

最后两行是整个评估的分水岭。

---

## 3. 分水岭：浏览器 JS 打不开命名管道

Aegis 的 GUI↔服务通道是 **命名管道 + 显式 DACL + 一次性 token**
（`SECURITY.md`、`design-spec.md` §23）。任何前端方案都得先回答：
**你打算怎么连上 `\\.\pipe\aegis`？**

实测（`/tmp/pipe-probe2.js`，用 `String.fromCharCode(92)` 拼名以绕开转义）：

```text
platform=win32  node=v22.22.2
--- dotslash: raw="\\\\.\\pipe\\aegis-probe-18092"
   listen ✓
   connect ✓
   echo ✓ "ECHO:HELLO"
```

- **Node 可以**：`net.createServer` / `net.connect` 直接吃 `\\.\pipe\name`。
- **浏览器不可以**：页面 JS 没有任何 API 能打开命名管道。这不是权限问题，
  是根本没有这个能力。

于是三个候选立刻分出胜负：

| 方案 | 谁来连管道 | 代价 |
|---|---|---|
| Tauri（Rust 壳） | 壳的 Rust 侧，**直接 `use aegis_ipc`** | 无 |
| Electron（Node 壳） | 主进程 `net.connect` | 要用 JS **重写一遍**帧编解码 + 握手 + token 流程 |
| 纯网页（浏览器） | **没人能连** → 必须额外写一个常驻桥进程 | 桥 + localhost 端口 |

⚠ 纯网页方案最容易被误判成"最简单"。它省掉了壳，但要补一个常驻的
桥进程，并且为了让浏览器能访问，桥必须监听 `127.0.0.1:<port>`：

- 命名管道有 **DACL** 精确控制谁能连；localhost 端口对**本机所有进程**可见；
- 浏览器还得防 DNS rebinding / 任意本地网页探测；
- 结果：多一个进程、多一个端口、安全性更差，复杂度并不比套个壳低。

**纯网页方案出局。**

---

## 4. Tauri vs Electron

| | **Tauri v2** | **Electron** |
|---|---|---|
| 连管道 | Rust 侧 **复用 `aegis_ipc`** | Node 侧用 JS **重新实现**线协议 |
| 协议漂移风险 | **零**（同一个 crate） | 有：Rust 改了字段，JS 得跟着改，改漏了不报错 |
| 硬前置 | MSVC + SDK + WebView2 → **本机全部满足**（实测） | 无（预编译二进制） |
| 产物体积 | 约 10 MB | 约 150 MB+ |
| 运行时依赖 | WebView2（已装） | 自带 Chromium + Node |
| 与后端同语言 | ✅ | ❌ |
| 生态 / 中文资料 | 较少 | 多 |
| 打包签名 | 要现学 | 成熟 |
| 工具链 | **需要 msvc**（见 §5） | 不需要 |

决定性的一条是**第一行**：Tauri 的壳是 Rust，能直接 `use aegis_ipc`——
`PipeClient`、`Status::from_text`、`IpcToken`、`normalize_pipe_name`、
帧编解码全是现成的。Electron 要把"握手 → 版本校验 → token 鉴权 →
发请求 → 收应答"这套流程在 JS 里再写一遍，而这套流程里有两条
**写错了不会报错、只会变弱**的细节：

- 握手必须在鉴权之前（版本谈不拢就不能把 token 送出去）；
- token 不对**不许自动重试**（重试会把"鉴权失败"变成慢速拒绝服务）。

这两条在 `aegisctl/src/main.rs` 里是注释加代码一起钉住的。抄一遍到 JS，
注释丢一半的概率很高。

---

## 5. Tauri 要付的账：双工具链

不能只说好处。Tauri 要求 **msvc 工具链**，而本项目是 **gnu 宿主**
（`rust-toolchain.toml` 显式固定 `stable-x86_64-pc-windows-gnu`）。

好消息是实测下来这条账比想象中小：

- `cargo +stable-x86_64-pc-windows-msvc build -p aegisd` → **55s 通过**，
  含完整 `windows` 0.58 绑定。**不需要切换默认工具链**，加号指定即可。
- **不需要设 `INCLUDE` / `LIB`**，也不需要把 `cl.exe` 放进 PATH——
  rustc 自己探测得到（清空环境实测通过）。
- `rust-toolchain.toml` 的 `targets` 里**已经列了** `x86_64-pc-windows-msvc`。

要付的实际代价：

| 代价 | 处理 |
|---|---|
| 磁盘多一份 msvc 的 target 目录 | 可接受；或给 UI 单独设 `CARGO_TARGET_DIR` |
| 每次要敲 `cargo +stable-x86_64-pc-windows-msvc` | ✅ 已落地：`ui/src-tauri/rust-toolchain.toml` 钉 msvc，后端仍走根目录的 gnu。**不能省**——gnu 的 windres 打不开中文路径下的 `icon.ico`（见 §9） |
| ⚠ gnu 与 msvc 同时装 **clippy** 会因 `cargo-clippy.exe` 同名冲突而回滚 | `rust-toolchain.toml` 注释里已记录；不要在该文件里声明 `components`，按需单独 `rustup component add` |
| CI 要装 MSVC | 用 `windows-latest` 镜像（自带） |

---

## 6. 落地步骤（每步都能单独回滚）

1. ✅ **抽公共客户端**（已完成，纯重构、输出逐字节一致）
   `aegis-ipc` 新增 `client` 模块，对外给两个入口：

   | 入口 | 给谁用 |
   |---|---|
   | `Session::connect()?.handshake()?.authenticate(&token)?.request(word)` | 需要**分步打印过程**的（如 `aegisctl`） |
   | `talk(pipe, &token, word)` | 只想要结果、不想管过程的（**GUI 用这个**） |

   两条纪律用**类型状态**钉死：`request()` 只挂在 `Session<Ready>` 上，
   而 `Ready` 只能由 `authenticate()` 产出、`Handshook` 只能由 `handshake()`
   产出。**顺序写反是编译错误**，不是"记得别写反"——有个 `compile_fail`
   文档测试专门守着这一点。

   验收方式：把旧版 `aegisctl` 从 git 取回来编一遍，两边输出**逐字节 diff 为空**。

2. ✅ **前端骨架**（已完成，不碰 Tauri）
   `ui/`：Vite 6 + Vue 3 + TypeScript + Tailwind 3 + Headless UI + Pinia。

   | 文件 | 作用 |
   |---|---|
   | `src/types.ts` | 与 `aegis-ipc` 的 `Status` **逐字段对应**；没有 IPC 字段的类型单独隔开并注明"不许自己造协议" |
   | `src/ipc.ts` | 桥接层。**没有任何协议实现**——解析在 Rust 侧，界面只消费 JSON |
   | `src/utils/format.ts` | 显示格式化。铁律与 `aegisctl` 同源：认不出的取值显示成 `**未知取值** x`，**不**回退成"正常" |
   | `src/stores/status.ts` | 状态存储 + 轮询 |
   | `src/components/DaemonUnreachable.vue` | 连不上守护进程时的大空态（把线索全摆出来） |
   | `src/layouts/` | 侧栏 + 顶栏 + **守卫横幅**（不可关闭） |
   | `src/views/` | 总览 / 守卫 / 网卡与角色 / 审计 / 设置 |

   五页骨架已成型，`vue-tsc --noEmit` 与 `vite build` 均通过。
   主题沿用既有项目的 5 套（`aegis` 为默认），令牌与组件类同名同义。

3. ✅ **接 Tauri**（已完成）
   `ui/src-tauri/`，**独立 workspace**（不并进根 workspace，理由见根
   `Cargo.toml` 的 `exclude` 注释：Tauri 要 msvc，后端是 gnu 宿主，
   混进来会让 CI 的「格式与静态检查」第一次就挂）。

   - Rust 侧只做三件事：解析端点 → 读 token → `aegis_ipc::talk`。
     **token 从头到尾不进渲染进程**。
   - 三个命令全是只读：`status` / `ping` / `endpoint_info`。
   - `Status` 的 JSON 由**派生**序列化（`aegis-ipc` 新增可选 `json` feature），
     不给外壳这边手写一个字段映射——手写就意味着字段有两处定义，
     `Status` 加字段时这里不会编译失败，只会静默少一列。
   - 端点不写死，走 `AEGIS_PIPE` / `AEGIS_TOKEN_FILE`；
     默认 token 路径 `%PROGRAMDATA%\Aegis\ipc.token`。

4. ✅ **轮询接真数据**（已完成）
   `REQ_STATUS` 是请求/响应式，做定时轮询（1.5s；断连时放慢到 4s）。
   **没有上推送**——推送要在服务端加事件通道，属于新增攻击面。

   ⚠ 一条必须守住的行为：**断连后不清空快照**。
   断网时人要看的正是"为什么断"，把界面清空等于把线索一起清了。
   所以 `snapshot` 一旦拿到就不再置回 `null`，改用 `stale` 标出来，
   界面显示"以下是最后一次成功的快照（时间）"。

5. ✅ **危险操作：改定成"不给按钮，给命令"**
   原计划是"接上 + 二次确认"。**实测权限模型后改了**：

   `aegis_ipc::peer::Risk::Dangerous`（`apply` / `confirm` / `rollback`）
   要求**对端进程已提权**（`peer::allows` + `token_is_elevated`），
   而 GUI 按设计**不提权**（§7）。所以危险命令从界面里**根本发不出去**——
   不是"还没接线"，是这个模型下不应该接。

   于是守卫页不画"解除收紧"按钮，改为给出能在管理员终端跑的命令。
   画按钮只会得到"点了没反应"，而人会以为什么都没做就已经恢复了——
   这比没有按钮更危险。

   > 若将来真要在界面里做危险操作，前提是先回答"GUI 凭什么提权"，
   > 而不是先画按钮。那是另一个立项。

---

## 7. 不可让步的约束

- **GUI 不提权**。提权只集中在 `aegisd`（SYSTEM）。
- **不新增 localhost 端口**。通道仍然只有命名管道那一条。
- **token 不进前端**。由 Tauri 的 Rust 侧读 token 文件、完成鉴权，
  渲染进程从头到尾拿不到 token。
- **UI 只读优先**。规则编辑、自更新这类写操作先不做。
- ⚠ **界面里不出现危险命令**（`apply` / `confirm` / `rollback`）。
  它们是 `Risk::Dangerous`，要求对端进程已提权，而 GUI 不提权。
  这不是"还没接线"，是这个模型下发不出去——详见 §6 第 5 步。

---

## 8. 不做的事

- 不在 UI 里做规则集编辑（先只读，避免 UI 变成第二个事实来源）。
- 不做自更新 UI（`design-spec.md` §28 路径 B）——自更新会动 SYSTEM 服务的
  二进制，错了就是变砖，优先级远低于"让人看懂当前状态"。
- 不为了"跨平台"引入任何抽象。本项目 Windows-only，WFP 也只有 Windows 有。

---

## 9. 复现命令

```bash
# 1. MSVC 到底在不在（查所有盘，别只查 C 盘）
"/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe" \
  -all -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
  -format value -property installationPath

# 2. msvc 工具链能不能编全项目（不需要设 INCLUDE/LIB）
cargo +stable-x86_64-pc-windows-msvc build -p aegisd

# 3. Node 能不能连命名管道
node -e "const n=require('net'),B=String.fromCharCode(92),p=B+B+'.pipe'+B+'probe'+process.pid;\
const s=n.createServer(c=>c.on('data',d=>c.write('ECHO:'+d)));\
s.listen(p,()=>{const c=n.connect(p,()=>c.write('HI'));c.on('data',d=>{console.log(d+'');process.exit(0)})});"
# 期望输出：ECHO:HI

# 4. WebView2 在不在
ls "/c/Program Files (x86)/Microsoft/EdgeWebView/Application"

# 5. 编外壳（msvc 工具链，独立于后端的 gnu）
cd ui/src-tauri
cargo +stable-x86_64-pc-windows-msvc check --all-targets

# 6. 跑起来（会先起 vite，再拉起窗口）
cd ui && npm run tauri:dev
```

> ⚠ **本机专有的坑**：系统残留了一个失效的 HTTP 代理（`127.0.0.1:7897`，
> 没有进程在监听），而 cargo 在 Windows 上会读**系统**代理设置
> （不是环境变量），于是所有 registry 访问都会超时失败，报错长这样：
>
> ```text
> warning: spurious network error: Failed to connect to rsproxy.cn:443 over proxy 127.0.0.1
> error: failed to get `serde` as a dependency ... download of config.json failed
> ```
>
> 后端之所以不受影响，是因为它的依赖早就在缓存里、不需要解析新依赖树。
> 外壳是**新 workspace**，第一次必须联网。
> 绕法：`export CARGO_HTTP_PROXY=""`（显式置空 = 强制直连）。

> ⚠ **第二个坑：gnu 的 windres 打不开中文路径下的 `icon.ico`**。
> `ui/src-tauri` 虽然已钉 msvc（见 §5），但如果哪天那份
> `rust-toolchain.toml` 丢了或被改名，rustup 会**向上找**到仓库根那份
> （gnu 宿主），于是 tauri-build 改用 mingw 的 windres 编 Windows 资源文件：
>
> ```text
> windres: can't open icon file `D:\Project\草稿箱\...\icon.ico': Invalid argument
> ```
>
> 这个报错**指向图标文件本身**，第一反应会去查图标是不是坏了、路径是不是写错，
> 实际是 windres 对路径里的中文（"草稿箱"）编码处理不了——查错方向要白折腾一圈。
> msvc 不经 windres，没有这个问题。所以 `ui/src-tauri/rust-toolchain.toml`
> 不是可选的仪式，是**必需**的：它必须在仓库中文路径下也能构建。
