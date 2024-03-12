import 'package:flutter/material.dart';
import 'package:bastion/pages/Signup.dart';
class LandingPage extends StatelessWidget {
  const LandingPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Color.fromARGB(98, 90, 86, 86),
      body: Container(
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Image.asset(
                'assets/logo/bastionwhite.png', // Updated image path
                width: 300, // Set the width of the image
                height: 300, // Set the height of the image
              ),
              const SizedBox(
                height: 20
              ), // Add some spacing
              
              ElevatedButton(
                child: Text('Continue'),
                  onPressed: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(builder: (context) => Signup()),
                    );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

}