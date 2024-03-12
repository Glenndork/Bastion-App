import 'package:flutter/material.dart';

class HomePage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Color.fromARGB(98, 90, 86, 86),
      body: Container(
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
            height: double.infinity,
            padding: const EdgeInsets.all(15),
            child: Stack(
              children: [
                Align(
                  alignment: Alignment.topLeft,
                  child: Image.asset(
                    'assets/logo/noname.png',
                    width: 150,
                    height: 150,
                  ),
                ),
                const Positioned(
                  top: 55, // Half of the image height to center the text vertically relative to the image
                  left: 150 + 15, // Image width + desired space between the image and the text
                  child: Text(
                    'BASTION',
                    style: TextStyle(
                      fontFamily: 'Black Ops One',
                      fontSize: 30,
                      color: Colors.white,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),

        Expanded(
          child: Container(
            height: double.infinity,
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    width: 350, // Adjust the size of the circle
                    height: 350, // Adjust the size of the circle
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: Colors.white,
                        width: 2, // Adjust the width of the circle border
                      ),
                    ),
                    child: const Center(
                      child: Icon(
                        Icons.check,
                        color: Colors.green,
                        size: 300, // Adjust the size of the checkmark
                      ),
                    ),
                  ),
                  const SizedBox(height: 10), // Adjust the spacing between the checkmark and the text
                  const Text(
                    'This computer is protected',
                    style: TextStyle(
                      fontSize: 30, // Adjust the font size of the text
                      color: Colors.white, // Adjust the color of the text
                    ),
                  ),
                  const Text(
                    'You are up-to-date! Last scanned today at 6:09 PM',
                    style: TextStyle(
                      fontSize: 18, // Adjust the font size of the text
                      color: Colors.white, // Adjust the color of the text
                    ),
                  ),
                  const SizedBox(height: 20), // Add spacing between the text and buttons
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      ElevatedButton(
                        onPressed: () {
                          // Add your logic for the "Disable" button
                        },
                        style: ButtonStyle(
                          backgroundColor: MaterialStateProperty.all<Color>(Colors.red), // Set the red color
                          shape: MaterialStateProperty.all<RoundedRectangleBorder>(
                            RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10), // Set the border radius
                            ),
                          ),
                          minimumSize: MaterialStateProperty.all<Size>(
                            Size(170, 65), // Set the width and height of the button
                          ),
                        ),
                        child: const Text(
                          'DISABLE',
                          style: TextStyle(
                            color: Colors.black,
                            fontSize: 24,
                            fontWeight: FontWeight.bold
                          ),
                          ),
                      ),
                      ElevatedButton(
                        onPressed: () {
                          // Add your logic for the "Run Scan" button
                        },
                        style: ButtonStyle(
                          backgroundColor: MaterialStateProperty.all<Color>(Colors.green), // Set the green color
                          shape: MaterialStateProperty.all<RoundedRectangleBorder>(
                            RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10), // Set the border radius
                            ),
                          ),
                          minimumSize: MaterialStateProperty.all<Size>(
                            Size(170, 65), // Set the width and height of the button
                          ),
                        ),
                        child: const Text(
                          'RUN SCAN',
                          style: TextStyle(
                            color: Colors.black,
                            fontSize: 24,
                            fontWeight: FontWeight.bold
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
        Expanded(
          child: Container(
            height: double.infinity,
            child: Stack(
              alignment: Alignment.topRight,
              children: [
                Padding(
                  padding: const EdgeInsets.all(15),
                  child: IconButton(
                    icon: const Icon(
                      Icons.settings, 
                      size: 40,
                      ),
                    onPressed: () {
                      // Add your logic for the settings icon
                    },
                    color: Colors.white, // Adjust the color of the settings icon
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
