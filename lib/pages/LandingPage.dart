import 'package:flutter/material.dart';
import 'package:bastion/pages/Signup.dart';
class LandingPage extends StatelessWidget {
  const LandingPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color.fromARGB(98, 90, 86, 86),
      body: Container(
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Image.asset(
                'assets/logo/bastionwhite.png', // Updated image path
                width: 400, // Set the width of the image
                height: 400, // Set the height of the image
              ),
              const SizedBox(
                height: 20
              ), // Add some spacing
              
              ElevatedButton(
                onPressed: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(builder: (context) => Signup()),
                  );
                },
                style: ButtonStyle(
                  minimumSize: MaterialStateProperty.all<Size>(Size(150, 50)), // Set the width and height of the button
                  foregroundColor: MaterialStateProperty.all<Color>(Colors.black), // Set the text color to black
                ),
                child: const Text(
                  'Continue',
                  style: TextStyle(fontSize: 18), // Adjust the font size
                ),
              ),

            ],
          ),
        ),
      ),
    );
  }

}