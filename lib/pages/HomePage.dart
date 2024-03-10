import 'package:flutter/material.dart';

class HomePage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return const Row(
      mainAxisAlignment: MainAxisAlignment.spaceEvenly, // Adjust as needed
      children: [
        Column(
          children: [
            Text('Column 1'),
          ],
        ),
        Column(
          children: [
            Text('Column 2'),
          ],
        ),
        Column(
          children: [
            Text('Column 3'),
          ],
        ),
      ],
    );
  }
}
