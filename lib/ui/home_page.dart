import 'dart:io';

import 'package:flutter/material.dart';

import '../core/extractor_controller.dart';
import '../core/protocol.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _controller = ExtractorController();
  final _userCtrl = TextEditingController(text: 'test');
  final _passCtrl = TextEditingController(text: '12345678');
  final _baseCtrl = TextEditingController(text: Protocol.defaultBaseUrl);
  final _outCtrl = TextEditingController();
  final _scrollCtrl = ScrollController();

  bool _obscure = true;
  int _lastLogCount = 0;

  @override
  void initState() {
    super.initState();
    _controller.addListener(_onChanged);
    _outCtrl.text = defaultOutputDir();
  }

  String defaultOutputDir() {
    final sep = Platform.pathSeparator;
    try {
      final home = Platform.environment['HOME'] ??
          Platform.environment['USERPROFILE'] ??
          Directory.current.path;
      return '$home${sep}MingLiveSlices';
    } catch (_) {
      return Directory.current.path;
    }
  }

  void _onChanged() {
    if (!mounted) return;
    setState(() {});
    if (_controller.logs.length != _lastLogCount) {
      _lastLogCount = _controller.logs.length;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_scrollCtrl.hasClients) {
          _scrollCtrl.animateTo(
            _scrollCtrl.position.maxScrollExtent,
            duration: const Duration(milliseconds: 180),
            curve: Curves.easeOut,
          );
        }
      });
    }
  }

  @override
  void dispose() {
    _controller.removeListener(_onChanged);
    _controller.dispose();
    _userCtrl.dispose();
    _passCtrl.dispose();
    _baseCtrl.dispose();
    _outCtrl.dispose();
    _scrollCtrl.dispose();
    super.dispose();
  }

  void _snack(String msg) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(msg)));
  }

  Future<void> _runLocal() async {
    _controller.baseUrl = _baseCtrl.text.trim();
    await _controller.loadCatalogAndVerify(memberOnly: true);
  }

  Future<void> _runLogin() async {
    if (_userCtrl.text.trim().isEmpty || _passCtrl.text.isEmpty) {
      _snack('请输入账号和密码');
      return;
    }
    _controller.baseUrl = _baseCtrl.text.trim();
    await _controller.login(_userCtrl.text.trim(), _passCtrl.text);
    if (_controller.session != null) {
      await _controller.fetchTransportKeys();
    }
  }

  Future<void> _runProbe() async {
    await _controller.probeSecureEndpoints();
  }

  Future<void> _runExtract() async {
    final out = Directory(_outCtrl.text.trim());
    await out.create(recursive: true);
    await _controller.runExtraction(
      outputDir: out,
      memberOnly: true,
      cipherOnly: true,
    );
  }

  @override
  Widget build(BuildContext context) {
    final c = _controller;
    final theme = Theme.of(context);
    final busy = c.busy;

    return Scaffold(
      appBar: AppBar(
        title: const Text('MingLive 资源重建'),
        actions: [
          IconButton(
            tooltip: '清空日志',
            onPressed: busy ? null : c.reset,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: LayoutBuilder(
        builder: (context, constraints) {
          final wide = constraints.maxWidth > 900;
          final left = _buildControls(context, c, busy);
          final right = _buildLog(context, c, theme);
          if (wide) {
            return Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                SizedBox(width: 420, child: SingleChildScrollView(child: left)),
                const VerticalDivider(width: 1),
                Expanded(child: right),
              ],
            );
          }
          return Column(
            children: [
              Expanded(flex: 3, child: SingleChildScrollView(child: left)),
              const Divider(height: 1),
              Expanded(flex: 5, child: right),
            ],
          );
        },
      ),
    );
  }

  Widget _buildControls(
      BuildContext context, ExtractorController c, bool busy) {
    final theme = Theme.of(context);
    final cat = c.catalog;

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('服务器', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _baseCtrl,
                    enabled: !busy,
                    decoration: const InputDecoration(
                      labelText: 'Base URL',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text('账号', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _userCtrl,
                    enabled: !busy,
                    decoration: const InputDecoration(
                      labelText: '用户名 / 邮箱',
                      border: OutlineInputBorder(),
                      isDense: true,
                      prefixIcon: Icon(Icons.person_outline),
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _passCtrl,
                    enabled: !busy,
                    obscureText: _obscure,
                    decoration: InputDecoration(
                      labelText: '密码',
                      border: const OutlineInputBorder(),
                      isDense: true,
                      prefixIcon: const Icon(Icons.lock_outline),
                      suffixIcon: IconButton(
                        icon: Icon(_obscure
                            ? Icons.visibility_off
                            : Icons.visibility),
                        onPressed: () =>
                            setState(() => _obscure = !_obscure),
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  FilledButton.icon(
                    onPressed: busy ? null : _runLogin,
                    icon: const Icon(Icons.login),
                    label: const Text('登录并拉取密钥'),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('执行步骤', style: theme.textTheme.titleSmall),
                  const SizedBox(height: 10),
                  OutlinedButton.icon(
                    onPressed: busy ? null : _runLocal,
                    icon: const Icon(Icons.folder_open),
                    label: const Text('1. 加载 catalog 并校验本地切片'),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton.icon(
                    onPressed: busy ? null : _runProbe,
                    icon: const Icon(Icons.radar),
                    label: const Text('2. 探测 secure 接口'),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _outCtrl,
                    enabled: !busy,
                    decoration: const InputDecoration(
                      labelText: '输出目录',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                  const SizedBox(height: 8),
                  FilledButton.tonalIcon(
                    onPressed: busy ? null : _runExtract,
                    icon: const Icon(Icons.download),
                    label: const Text('3. 重建 MEMBER 资源'),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          if (cat != null) _buildCatalogCard(context, c, cat),
          if (c.session != null) _buildSessionCard(context, c),
          if (busy || c.progressTotal > 0) _buildProgress(context, c),
        ],
      ),
    );
  }

  Widget _buildCatalogCard(
      BuildContext context, ExtractorController c, cat) {
    final theme = Theme.of(context);
    final inv = c.inventory;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('资源清单', style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            _kv('资源总数', '${cat.resources.length}'),
            _kv('MEMBER 资源', '${cat.memberResources.length}'),
            _kv('FREE 资源', '${cat.freeResources.length}'),
            _kv('远端字节 (MEMBER)', '${cat.memberRemoteBytes}'),
            _kv('contentKeyId', '${cat.contentKeyId}'),
            if (inv != null) ...[
              const Divider(height: 18),
              _kv('本地校验通过', '${inv.verified}'),
              _kv('缺失切片', '${inv.missing.length}'),
              _kv('大小不符', '${inv.sizeMismatch.length}'),
              _kv('哈希不符', '${inv.hashMismatch.length}'),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSessionCard(BuildContext context, ExtractorController c) {
    final theme = Theme.of(context);
    final s = c.session!;
    final m = s.user.membership;
    final isMember = m.grantsMemberAccess;
    return Card(
      color: isMember
          ? theme.colorScheme.primaryContainer
          : theme.colorScheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(isMember ? Icons.verified : Icons.block,
                    size: 18),
                const SizedBox(width: 6),
                Text(isMember ? '会员已激活' : '非会员',
                    style: theme.textTheme.titleSmall),
              ],
            ),
            const SizedBox(height: 8),
            _kv('用户', s.user.username),
            _kv('角色', s.user.role),
            _kv('会员等级', m.tier),
            _kv('到期', '${m.expiresAt ?? '-'}'),
            if (c.transportKeys != null)
              _kv('传输密钥', c.transportKeys!.activeKeyId),
          ],
        ),
      ),
    );
  }

  Widget _buildProgress(BuildContext context, ExtractorController c) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            LinearProgressIndicator(
              value: c.progressTotal == 0 ? null : c.progress,
            ),
            const SizedBox(height: 8),
            Text(
              '${c.stage.name}  ${c.progressDone}/${c.progressTotal}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            if (c.currentPath != null)
              Text(
                c.currentPath!,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context).textTheme.bodySmall,
              ),
          ],
        ),
      ),
    );
  }

  Widget _kv(String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 130,
              child: Text(k,
                  style: const TextStyle(fontSize: 12, color: Colors.grey)),
            ),
            Expanded(
              child: SelectableText(v,
                  style: const TextStyle(fontSize: 12)),
            ),
          ],
        ),
      );

  Widget _buildLog(
      BuildContext context, ExtractorController c, ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
          child: Row(
            children: [
              Text('运行日志', style: theme.textTheme.titleSmall),
              const Spacer(),
              if (c.error != null)
                Flexible(
                  child: Text(
                    c.error!,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                        color: theme.colorScheme.error, fontSize: 12),
                  ),
                ),
            ],
          ),
        ),
        Expanded(
          child: Container(
            margin: const EdgeInsets.fromLTRB(16, 4, 16, 16),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(8),
            ),
            child: c.logs.isEmpty
                ? const Center(
                    child: Text('等待执行…',
                        style: TextStyle(color: Colors.grey)),
                  )
                : Scrollbar(
                    controller: _scrollCtrl,
                    thumbVisibility: true,
                    child: ListView.builder(
                      controller: _scrollCtrl,
                      itemCount: c.logs.length,
                      itemBuilder: (context, i) => SelectableText(
                        c.logs[i],
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 11.5,
                          height: 1.45,
                        ),
                      ),
                    ),
                  ),
          ),
        ),
      ],
    );
  }
}
