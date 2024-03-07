import 'package:flutter/material.dart';

class LandingPage extends StatelessWidget {
  const LandingPage({super.key});
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          color: const Color.fromARGB(255, 50, 51, 49)
        ),
        child: const Center(
          child: Column(
            children: [
              Row(
                children: [
                  Column(
                  // Container(
                  //   decoration: BoxDecoration(
                  //     color: Colors.lightGreen,
                  //   ),
                  //   child: Text("tanignamo"),
                  // ),
                  ),
                ]
              ),
            ],
          ),
        ),
      )
      
    );
  }

}