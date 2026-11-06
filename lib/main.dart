import 'package:flutter/material.dart';

import 'ui/home_page.dart';

void main() {
  runApp(const MingLiveExtractorApp());
}

class MingLiveExtractorApp extends StatelessWidget {
  const MingLiveExtractorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'MingLive 资源重建',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF2E7D32),
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF2E7D32),
        brightness: Brightness.dark,
      ),
      home: const HomePage(),
    );
  }
}
