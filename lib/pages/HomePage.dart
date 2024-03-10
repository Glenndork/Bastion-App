import 'package:flutter/material.dart';

class HomePage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        color: Colors.grey,
        child: ThreeColumnsRow(),
      ),
    );
  }
}

class ThreeColumnsRow extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: Container(
            height: double.infinity, // Maximum height for Column 1
            child: Center(
              child: Text('Column 1'),
            ),
          ),
        ),
        Expanded(
          child: Container(
            height: double.infinity, // Maximum height for Column 1
            child: Center(
              child: Text('Column 2'),
            ),
          ),
        ),
        Expanded(
          child: Container(
            height: double.infinity, // Maximum height for Column 1
            child: Center(
              child: Text('Column 3'),
            ),
          ),
        ),
      ],
    );
  }
}
