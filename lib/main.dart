import 'package:flutter/material.dart';
import 'package:bastion/pages/LandingPage.dart';
import 'package:bastion/pages/home.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: "Bastion",
      debugShowCheckedModeBanner: false,
      home: LandingPage(),
    );
  }
  
}
