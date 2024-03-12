import 'package:flutter/material.dart';
import 'HomePage.dart'; // Import the file representing your homepage

class Signup extends StatefulWidget {
  @override
  _SignupState createState() => _SignupState();
}

class _SignupState extends State<Signup> {
  TextEditingController nameController = TextEditingController();
  TextEditingController phoneNumberController = TextEditingController();

  String nameError = ''; // Initialize with an empty string
  String phoneNumberError = ''; // Initialize with an empty string

  bool isValidPhoneNumber(String phoneNumber) {
    // Add your phone number validation logic here
    // For simplicity, this example checks if the number starts with '+63'
    return phoneNumber.startsWith('+63');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Color.fromARGB(98, 90, 86, 86),
      body: Center(
        child: Container(
          width: 350,
          height: 550,
          decoration: BoxDecoration(
            color: const Color.fromARGB(255, 216, 212, 212),
            borderRadius: BorderRadius.circular(20), // Add border radius here
          ),
          child: Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                Image.asset(
                  'assets/Logo/bastionwhite.png', // Replace with your logo asset path
                  height: 250,
                  width: 250,
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: nameController,
                  decoration: InputDecoration(
                    hintText: 'Enter your name',
                    errorText: nameError,
                    focusedBorder: const UnderlineInputBorder(
                      borderSide: BorderSide(color: Colors.grey),
                    ),
                  ),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: phoneNumberController,
                  decoration: InputDecoration(
                    hintText: 'Enter your phone number',
                    errorText: phoneNumberError,
                  ),
                ),
                const SizedBox(height: 20),
                ElevatedButton(
                  onPressed: () {
                    // Validate name and phone number before proceeding
                    // setState(() {
                    //   nameError = '';
                    //   phoneNumberError = '';

                    //   if (nameController.text.isEmpty) {
                    //     nameError = 'Name is required';
                    //   }

                    //   if (phoneNumberController.text.isEmpty || !isValidPhoneNumber(phoneNumberController.text)) {
                    //     phoneNumberError = 'Enter a valid Philippine phone number (starting with +63)';
                    //   }

                    //   // Proceed only if there are no errors
                    //   if (nameError.isEmpty && phoneNumberError.isEmpty) {
                    //     // Add your logic for the continue button
                    //     // For example, you can navigate to the next screen (Homepage)
                    //     Navigator.push(
                    //       context,
                    //       MaterialPageRoute(builder: (context) => HomePage()),
                    //     );
                    //   }
                    // });

                    Navigator.push(
                      context,
                      MaterialPageRoute(builder: (context) => HomePage()),
                    );

                  },
                  style: ButtonStyle(
                    backgroundColor: MaterialStateProperty.all<Color>(Colors.grey[800]!),
                    foregroundColor: MaterialStateProperty.all<Color>(Colors.white),
                  ),
                  child: const Text('Continue'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
