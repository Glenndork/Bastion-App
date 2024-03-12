import 'package:flutter/material.dart';
import 'dart:async';
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

class ThreeColumnsRow extends StatefulWidget {
  @override
  _ThreeColumnsRowState createState() => _ThreeColumnsRowState();
}

class _ThreeColumnsRowState extends State<ThreeColumnsRow> {
  IconData iconData = Icons.check;
  Color iconColor = Colors.green;
  String statusText = 'This computer is protected';
  String buttonText = 'DISABLE';
  Color buttonColor = Colors.red;
  bool isScanRunning = false;
  String elapsedTime = '00:00:00';
  late Timer scanTimer; // Declare the Timer variable
  int elapsedSeconds = 0;
  int detectedMalwares = 0;

  @override
  void dispose() {
    // Dispose the timer when the widget is disposed
    scanTimer.cancel();
    super.dispose();
  }

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
                    width: 100,
                    height: 100,
                  ),
                ),
                const Positioned(
                  top: 30,
                  left: 100 + 5,
                  child: Text(
                    'BASTION',
                    style: TextStyle(
                      fontFamily: 'Black Ops One',
                      fontSize: 25,
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
                    width: 350,
                    height: 350,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: Colors.white,
                        width: 2,
                      ),
                    ),
                    child: Center(
                      child: Icon(
                        iconData,
                        color: iconColor,
                        size: 300,
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  isScanRunning
                      ? Text(
                          'Scanning...',
                          style: const TextStyle(
                            fontSize: 30,
                            color: Colors.white,
                          ),
                        )
                      : Text(
                          statusText,
                          style: const TextStyle(
                            fontSize: 30,
                            color: Colors.white,
                          ),
                        ),
                  const SizedBox(height: 10),
                  isScanRunning
                      ? Text(
                          'Elapsed Time: $elapsedTime',
                          style: const TextStyle(
                            fontSize: 18,
                            color: Colors.white,
                          ),
                        )
                      : const Text(
                          'You are up-to-date! Last scanned today at 6:09 PM',
                          style: TextStyle(
                            fontSize: 18,
                            color: Colors.white,
                          ),
                        ),
                        const SizedBox(height: 10),
                        Visibility(
                          visible: isScanRunning,
                          child: Text(
                            'Detected Malwares: $detectedMalwares',
                            style: const TextStyle(
                              fontSize: 18,
                              color: Colors.white,
                            ),
                          ),
                        ),
                  const SizedBox(height: 20),
                  Row(
                    mainAxisAlignment: isScanRunning ? MainAxisAlignment.center : MainAxisAlignment.spaceEvenly,
                    children: [
                      Visibility(
                        visible: !isScanRunning,
                        child: ElevatedButton(
                          onPressed: () {
                            setState(() {
                              if (buttonText == 'DISABLE') {
                                iconData = Icons.clear;
                                iconColor = Colors.red;
                                statusText = 'This computer is not protected';
                                buttonText = 'ENABLE';
                                buttonColor = Colors.green;
                              } else {
                                iconData = Icons.check;
                                iconColor = Colors.green;
                                statusText = 'This computer is protected';
                                buttonText = 'DISABLE';
                                buttonColor = Colors.red;
                              }
                            });
                          },
                          style: ButtonStyle(
                            backgroundColor: MaterialStateProperty.all<Color>(buttonColor),
                            shape: MaterialStateProperty.all<RoundedRectangleBorder>(
                              RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(10),
                              ),
                            ),
                            minimumSize: MaterialStateProperty.all<Size>(
                              const Size(170, 65),
                            ),
                          ),
                          child: Text(
                            buttonText,
                            style: const TextStyle(
                              color: Colors.black,
                              fontSize: 24,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ),
                      ElevatedButton(
                        onPressed: isScanRunning
                            ? () {
                                // Add your logic for stopping the scan
                                setState(() {
                                  isScanRunning = false;
                                  iconData = Icons.check;
                                  buttonText = 'DISABLE';
                                  buttonColor = Colors.red;
                                  iconColor = Colors.green;
                                  scanTimer.cancel();
                                  elapsedSeconds = 0;
                                  detectedMalwares = 0;
                                });
                              }
                            : () {
                                // Add your logic for starting the scan
                                setState(() {
                                  isScanRunning = true;
                                  iconData = Icons.search;
                                  iconColor = Colors.grey;
                                  buttonText = 'STOP';
                                  buttonColor = Colors.grey;
                                  startScan();
                                });
                              },
                        style: ButtonStyle(
                          backgroundColor: MaterialStateProperty.all<Color>(Colors.green),
                          shape: MaterialStateProperty.all<RoundedRectangleBorder>(
                            RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10),
                            ),
                          ),
                          minimumSize: MaterialStateProperty.all<Size>(
                            const Size(170, 65),
                          ),
                        ),
                        child: Text(
                          isScanRunning ? 'STOP' : 'RUN SCAN',
                          style: const TextStyle(
                            color: Colors.black,
                            fontSize: 24,
                            fontWeight: FontWeight.bold,
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
                    color: Colors.white,
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  void startScan() {
    const oneSec = Duration(seconds: 1);
    scanTimer = Timer.periodic(oneSec, (Timer timer) {
      setState(() {
        elapsedTime = Duration(seconds: timer.tick).toString().split('.').first;
      });
    });
  }
}
