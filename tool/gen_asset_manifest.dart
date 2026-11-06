// Generates the complete Flutter asset manifest for the slice tree.
//
// Flutter has no glob support in `pubspec.yaml`, and a bare directory entry
// only includes a directory's *immediate* children. The slice tree is nested
// (`effects/audio`, `effects/images`, `effects/videos/<name>`, `generated/...`),
// so every file must be listed individually. This tool walks
// `assets/builtin-slices` and rewrites the `assets:` block of `pubspec.yaml`
// with the full list, preserving all other content.
//
// Usage:
//   dart run tool/gen_asset_manifest.dart            # rewrite pubspec.yaml
//   dart run tool/gen_asset_manifest.dart --check    # fail if out of date
//   dart run tool/gen_asset_manifest.dart --print    # write to stdout only
import 'dart:io';

const String root = 'assets/builtin-slices';
const String pubspecPath = 'pubspec.yaml';
const String marker = '  assets:';

void main(List<String> args) {
  final check = args.contains('--check');
  final printOnly = args.contains('--print');

  final dir = Directory(root);
  if (!dir.existsSync()) {
    stderr.writeln('assets directory missing: $root');
    if (check) exit(1);
    return;
  }

  final files = dir
      .listSync(recursive: true, followLinks: false)
      .whereType<File>()
      .where((f) => f.path.endsWith('.part') || f.path.endsWith('catalog.json'))
      .map((f) => f.path.replaceAll('\\', '/'))
      .toList()
    ..sort();

  if (files.isEmpty) {
    stderr.writeln('no slice files found under $root');
    if (check) exit(1);
    return;
  }

  final buffer = StringBuffer()
    ..writeln(marker)
    ..writeln('    - $root/catalog.json');
  for (final f in files) {
    if (f.endsWith('catalog.json')) continue;
    buffer.writeln('    - $f');
  }
  final generated = buffer.toString();

  if (printOnly) {
    stdout.write(generated);
    return;
  }

  final file = File(pubspecPath);
  if (!file.existsSync()) {
    stderr.writeln('missing $pubspecPath');
    exit(1);
  }
  final src = file.readAsStringSync();
  final replaced = _replaceAssetsBlock(src, generated);

  if (check) {
    if (replaced != src) {
      stderr.writeln('pubspec.yaml asset manifest is stale; '
          'run: dart run tool/gen_asset_manifest.dart');
      exit(1);
    }
    stdout.writeln('asset manifest up to date (${files.length} files)');
    return;
  }

  file.writeAsStringSync(replaced);
  stdout.writeln('wrote ${files.length} asset entries into $pubspecPath');
}

/// Replaces the `assets:` block (its header plus every following more-indented
/// line) with [block], leaving the rest of the file untouched.
String _replaceAssetsBlock(String src, String block) {
  final lines = src.split('\n');
  final out = <String>[];
  var i = 0;
  var replaced = false;

  while (i < lines.length) {
    final line = lines[i];
    if (!replaced && line.trimRight() == marker.trimRight()) {
      out.add(block.trimRight());
      i++;
      // Skip the block body: lines that are blank or start with more indent.
      while (i < lines.length) {
        final l = lines[i];
        if (l.trim().isEmpty) {
          i++;
          continue;
        }
        if (l.startsWith('    ') || l.startsWith('\t')) {
          i++;
          continue;
        }
        break;
      }
      replaced = true;
      continue;
    }
    out.add(line);
    i++;
  }

  if (!replaced) {
    // No assets block yet: append one under `flutter:`.
    final idx = out.indexWhere((l) => l.trimRight() == 'flutter:');
    if (idx >= 0) {
      out.insertAll(idx + 1, ['', block.trimRight()]);
    } else {
      out
        ..add('flutter:')
        ..add(block.trimRight());
    }
  }

  return out.join('\n');
}
