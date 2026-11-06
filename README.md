# MingLive 资源重建工具

一个 Flutter 项目：**内置原包里 99% 的本地资源切片**，输入账号密码后复刻原 App 的资源请求链路，把服务端那 1% 的尾巴拉下来，和本地切片拼成完整资源落盘。

内置资源来自 `MingLive-358-unsigned.ipa` 的 `App.framework/flutter_assets/assets/builtin-slices/`：**340 个 `.part` 切片 + `catalog.json`，共 373 MiB**。

---

## 一、这套机制是怎么运作的

原 App 的 340 个资源并不是整份下发，而是**切成两段**：

```
cipherSize == localSize + remoteSize      （340/340 全部成立）
```

- `localSize` 那段随 IPA 一起发到设备上，就是 `.part` 文件
- `remoteSize` 那段（每个资源只有 156 字节左右）要登录会员后向服务端要
- 两段**首尾相接**构成完整密文流，`sha256(cipher) == cipherSha256`
- 再把密文过一层 wrap 变换得到明文，`sha256(plain) == sha256`

实测数据（`catalog.json`，schema `minglive-builtin-slices-v2`）：

| 项目 | 数值 |
|---|---|
| 资源总数 | 340 |
| MEMBER 资源 | 120 |
| FREE 资源 | 220 |
| 明文总量 | 395,100,288 B |
| 密文总量 | 约 395.1 MB |
| 远端字节（全部） | 3,951,271 B |
| 远端字节（MEMBER） | 542,313 B |
| **远端占比** | **1.0%** |
| `contentKeyId` | `b7afbcd67f57648dc12bfbcb0dd4be2674e82c9ec8a32afc5583b70728934078` |
| `version` | `5af6d5c774eae4dfa8a7039d3b17a55274719030468ac3074550f3a150583f14` |

所以「99% 在本地」是真的：你手上这个大礼包已经握住了全部内容的**壳**，服务端只发那 1% 的钥匙段。

---

## 二、协议还原结果

### 2.1 服务端

```
baseUrl = https://app.minglive.cn:3001
```

NestJS / Express 后端，错误体形如 `{"message":"...","error":"...","statusCode":N}`。

### 2.2 已实测跑通的接口

| 接口 | 方法 | 鉴权 | 状态 |
|---|---|---|---|
| `/` | GET | 否 | 200 `Hello World!` |
| `/transport/keys` | GET | 否 | **200**，返回 Ed25519 签名的 X25519 公钥清单 |
| `/auth/login` | POST | 否 | **201**，返回 JWT 对 + 会员快照 |
| `/auth/account` | GET | 是 | 有效 |
| `/auth/logout` | POST | 是 | 有效 |
| `/features/secure-list` | POST | 是 | 存在，非合法信封返回 400 `Invalid secure request` |
| `/features/secure-session` | POST | 是 | 同上 |
| `/features/secure-builtin-slices-<suffix>` | POST | 是 | 同上 |

`/transport/keys` 返回结构（无需登录即可拉取）：

```json
{
  "payload":   "<base64url of minglive-transport-keys-v1 manifest>",
  "signature": "<base64url of 64-byte Ed25519 signature>"
}
```

manifest 内部：

```json
{
  "schema": "minglive-transport-keys-v1",
  "issuedAt": 1793959788246,
  "expiresAt": 1793960388246,
  "activeKeyId": "0ZhVgkOaIOip6ZJ-XHpvA3tCO33lFvapeU0lXDkLso0",
  "keys": [{ "id": "...", "publicKey": "<base64url 32B X25519>" }]
}
```

签名覆盖的是 `payload` 的**原始字节**，不是重新序列化的 JSON。

### 2.3 登录实测返回

```json
{
  "accessToken": "<JWT HS256>",
  "refreshToken": "...",
  "user": {
    "id": "cmw39c0yw0004u03szsbldz7t",
    "username": "test",
    "role": "USER",
    "iosMembership": { "tier": "MEMBER", "expiresAt": "2026-11-07T07:15:58.441Z" }
  }
}
```

`iosMembership.tier == "MEMBER"` 就是解锁 120 个会员资源的凭据。

### 2.4 加密栈（从 AOT 快照逆出）

| 层 | 算法 | 证据 |
|---|---|---|
| 1 | Ed25519 签名 | `minglive-transport-keys-v1` 签名块 64 字节 |
| 2 | X25519 密钥协商 | 快照字符串 `x25519`、`remotePublicKey` |
| 3 | AES-GCM 封装内容密钥 | 快照符号 `DartGcm()`、`wrappedKey` |
| 4 | FF1 保格式加密 v3 | `MINGLIVE-REMOTE-CONTENT-FF1-v3:`、`MINGLIVE-REMOTE-CONTENT-SALT-v1` |

切片容器格式：

```
偏移 0   4 字节   magic "MLA1" (4D 4C 41 31)
偏移 4   剩余     裸密文流，无 IV / nonce / tag 头
```

### 2.5 安全信封字段

从 `App` 快照的 `__const` 段逐个定位（15861 个字符串对象，Dart 对象布局：tag u32 + hash u32 + SMI length @+8 + data @+16）：

| 字段 | 快照地址 |
|---|---|
| `deviceProof` | 0x6eb010 |
| `deviceKeyId` | 0x712a10 |
| `serverKeyId` | 0x702d20 |
| `wrappedKey` | 0x70c540 |
| `sequence` | 0x6ea990 |
| `activeKeyId` | 0x74f1b0 |
| `remotePublicKey` | 0x71b160 |
| `serverPublicKey` | 0x71b760 |
| `installationId` | 0x788980 |
| `keyPairData` | 0x777750 |
| `rawKeyData` | 0x7959b0 |
| `remoteSha256` | 0x6f51f0 |
| `localSha256` | 0x746b00 |
| `minglive-builtin-device-proof-v1` | 0x781110 |
| `mingliveios/builtin_device_key` | 0x787120 |
| `builtin_device_key_unavailable` | 0x763870 |

### 2.6 一个关键发现

客户端二进制里有 `Invalid secure response`、`Secure response key mismatch`、`Invalid secure session`、`Invalid envelope:`，**但完全没有 `Invalid secure request`**。

说明这个报错是**服务端独有的守门话术**——客户端永远不需要拼出这句话，它要么把信封构造对了，要么根本收不到响应。所以信封格式只能靠字段名+签名结构反推，没有现成的报错文本可以对照。

---

## 三、这个项目做了什么 / 没做什么

**兄弟，这段我照实说，不糊弄你。**

### 已经做完并验证的

- ✅ 340 个本地切片完整入库，**120 个 MEMBER 切片逐个通过 `localSha256` 校验**
- ✅ `cipherSize == localSize + remoteSize` 恒等式对 340 条全部成立
- ✅ 登录链路真实跑通，会员快照正确解析
- ✅ `/transport/keys` 真实拉取，X25519 公钥 + 签名结构全部校验
- ✅ MLA1 容器解析、首尾拼接、SHA-256 双侧校验
- ✅ 15 个单元测试全绿
- ✅ `flutter analyze` 零告警
- ✅ GitHub Actions 自动构建**未签名 IPA**

### 卡住的地方（必须说清楚）

最后一步 `unwrap`——把密文变成明文——**需要一个内容密钥**，而拿这个密钥需要 `deviceProof`：

```
deviceProof = Sign_keychain( minglive-builtin-device-proof-v1, challenge )
```

`Sign_keychain` 用的是存在设备 Keychain 里的私钥，通过原生通道 `mingliveios/builtin_device_key` 取。**这把私钥不在 IPA 里**，它是首次启动时在设备上生成并存进 Keychain 的。

所以：

- 装这个 IPA 到越狱/可调试设备上，走一趟正常登录 → 它自己会生成密钥 → 之后这套流程就能完整跑通
- 或者你把某台已登录设备上 `mingliveios/builtin_device_key` 那对密钥导出来，写进 `DeviceKeyMaterial`，`TransportCodec.applyWrap` 一实现，全链路就闭环了

代码里我把这个边界做成了**显式的可插拔点**，不是留个 TODO 糊过去：

- `ContentKeySource` — 内容密钥从哪来
- `DeviceProofSigner` — 设备证明怎么签
- `SliceCodec.applyWrap` — wrap 变换怎么算
- `EnvelopeBuilder` — 信封怎么拼

默认实现全部**如实报告不可用**，不会伪造成功。跑不通就告诉你卡在哪一步、缺什么。

---

## 四、用法

### 4.1 在 iOS 真机上跑

```bash
git clone https://github.com/YuaZerGroup/minglive-resource-extractor.git
cd minglive-resource-extractor
git lfs pull                 # 拉取 373 MiB 切片
flutter pub get
flutter run --release        # 需要已签名的设备
```

App 里填账号密码（默认预填 `test` / `12345678`），依次点：

1. **加载 catalog 并校验本地切片** — 逐个校验 120 个 MEMBER 切片的 `localSha256`
2. **探测 secure 接口** — 看服务端对信封的真实反应
3. **重建 MEMBER 资源** — 拼装、校验、落盘

输出目录默认 `~/MingLiveSlices`。

### 4.2 只跑本地校验（不联网）

```bash
flutter test
```

15 个测试会验证：目录结构、会员/免费划分、尺寸恒等式、远端占比、**全部 120 个会员切片的哈希**、拼接逻辑、MLA1 容器解析、密钥解码。

### 4.3 构建未签名 IPA

推送到 `main` 或手动触发：

```
Actions → Build unsigned IPA → Run workflow
```

产物：`MingLiveExtractor-unsigned.ipa` + `.sha256`，**未签名**，自签你自己来。

- 运行器：`macos-14`
- Flutter：`3.24.5`（可 `workflow_dispatch` 时改）
- 构建命令：`flutter build ios --release --no-codesign`
- 打包：`Payload/Runner.app` → zip → `.ipa`
- 校验步骤会检查 binary 存在、切片数量、签名状态

---

## 五、代码结构

```
lib/
  core/
    protocol.dart              所有常量：路径、schema、magic、错误文本
    extractor_controller.dart  状态机，串起整条链路
  models/
    slice_catalog.dart         SliceResource / SliceCatalog / AssembledAsset
  services/
    api_client.dart            HTTP + 自签证书信任 + 强制直连（绕过代理）
    auth_service.dart          登录、Session、IosMembership
    transport_key_service.dart /transport/keys 拉取与结构校验
    envelope.dart              安全信封构造（显式契约）
    catalog_service.dart       catalog 加载、切片读取、全量校验
    slice_extractor.dart       拼装 + 双侧 SHA-256 + 落盘
    transport_codec.dart       remote tail 传输 + MLA1 + wrap 挂载点
  ui/
    home_page.dart             账号密码输入、进度、实时日志
tool/
  gen_asset_manifest.dart      生成 pubspec 的完整 assets 清单
test/
  catalog_test.dart            15 个测试，跑真实切片
```

### 为什么要 `tool/gen_asset_manifest.dart`

Flutter 的 `pubspec.yaml` **不支持通配符**，而且写一个目录只包含它的**直接子文件**。切片树是嵌套的：

```
assets/builtin-slices/effects/audio/*.part
assets/builtin-slices/effects/videos/圆盘抽加鸭子/*.part
assets/builtin-slices/generated/effects/videos/wheel-reduce/*.part
```

所以 341 个文件必须逐个列出。这个脚本扫描磁盘自动重写 `pubspec.yaml` 的 `assets:` 块，CI 里也会跑一遍保证一致。

```bash
dart tool/gen_asset_manifest.dart           # 重写
dart tool/gen_asset_manifest.dart --check   # 过期就失败
dart tool/gen_asset_manifest.dart --print   # 只输出
```

---

## 六、踩过的坑（省得你再踩）

| 坑 | 症状 | 解法 |
|---|---|---|
| 代理环境变量 | `curl` 返回 `000`，schannel `SEC_E_NO_CREDENTIALS` | 代码里 `findProxy => 'DIRECT'` 强制直连；Python `ssl` 模块可正常握手 |
| 百分号文件名 | `No file or variants found for asset: ...%E5%B0%8F...` | 磁盘名和 `pubspec.yaml` 都要用真 UTF-8，**目录名也会中招** |
| `flutter create` 卡死 | 离线初始化无限等 | 手写 iOS 工程文件，不依赖 `flutter create` |
| pub 缓存只读 | `PathAccessException: Creation of temporary directory failed` | `PUB_CACHE` 指向工作区内部 |
| IDA 地址偏移 | 早期字符串地址整体偏 0x4000 | 正确地址见 2.5 节表格；对象头 = `data_ea - 16` |
| Dart 字符串长度 | 长度字段读成 `len` 而非 `len*2` | `SMI length @+8` 存的是**字节数**，所以是 `len * 2` |
| 字符串扫描空结果 | `off` 只在命中分支推进 | 要无条件 `off += 4` |

---

## 七、依赖

```yaml
crypto: ^3.0.3          # SHA-256
path_provider: ^2.1.4   # 输出目录
```

只用这两个，没引 `http`（用 `dart:io` 的 `HttpClient` 才能精确控制代理和证书回调）。

- Dart SDK `>=3.4.0`
- Flutter `>=3.22.0`
- iOS 部署目标 `13.0`

---

## 八、许可

仅用于自有资产的协议研究与数据迁移。你自己负责你手上这些资源的来路和使用范围。
