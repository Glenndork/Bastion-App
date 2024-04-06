import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'dart:async';
import 'dart:io';

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
  late Timer scanTimer;
  int elapsedSeconds = 0; // Define elapsedSeconds here
  late StreamSubscription<FileSystemEntity> scanSubscription; // Add subscription for scanning
  int detectedMalwares = 0;
  String? directoryPath;

  @override
  void dispose() {
    scanTimer.cancel();
    scanSubscription.cancel(); // Cancel subscription when disposing
    super.dispose();
  }

   @override
  void initState() {
    super.initState();
    elapsedSeconds = 0; // Initialize elapsedSeconds in initState
  }

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
                      ? const Text(
                          'Scanning: ',
                          style: TextStyle(
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
                    mainAxisAlignment:
                        isScanRunning ? MainAxisAlignment.center : MainAxisAlignment.spaceEvenly,
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
                        onPressed: handleScanButtonPressed,
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
                      showDialog(
                        context: context,
                        builder: (BuildContext context) {
                          return AlertDialog(
                            title: Text("Settings"),
                            content: Text("XD"),
                            contentPadding: EdgeInsets.symmetric(horizontal: 50.0, vertical: 150.0),
                            actions: <Widget>[
                              TextButton(
                                onPressed: () {
                                  Navigator.of(context).pop();
                                },
                                child: Text("Close"),
                              ),
                            ],
                          );
                        },
                      );
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

  Future<void> _scanFilesAndChangeIcons(String directoryPath) async {
    final directory = Directory(directoryPath);

    if (!directory.existsSync()) {
      print('Directory does not exist: $directoryPath');
      return;
    }

    scanSubscription = directory.list(recursive: true).listen((entity) async {
      if (entity is File) {
        // Update UI to indicate scanning
        setState(() {
          iconData = Icons.search;
          iconColor = Colors.grey;
        });

        // Perform scanning logic
        print('Scanning File: ${entity.path}');
        print('File Type: ${entity.path.split('.').last}');

        // Simulate scanning delay
        await Future.delayed(Duration(milliseconds: 500)); // Adjust delay as needed
      }
    }, onDone: () {
      // Scan completed
      setState(() {
        isScanRunning = false;
        iconData = Icons.check;
        buttonColor = Colors.red;
        iconColor = Colors.green;
      });
    });

    // Start timer to track elapsed time
    const oneSec = Duration(seconds: 1);
    scanTimer = Timer.periodic(oneSec, (Timer timer) {
      setState(() {
        final duration = Duration(seconds: timer.tick);
        elapsedTime = '${duration.inHours}:${duration.inMinutes.remainder(60)}:${duration.inSeconds.remainder(60)}';
      });
    });
  }

  void startScan(String directoryPath) {
    setState(() {
      // Reset timer to zero when scanning starts
      elapsedTime = '00:00:00';
    });

    // Start the timer
    const oneSec = Duration(seconds: 1);
    int elapsedSeconds = 0;

    scanTimer = Timer.periodic(oneSec, (Timer timer) {
      setState(() {
        // Update elapsed time every second
        elapsedSeconds++;
        final hours = (elapsedSeconds / 3600).floor();
        final minutes = ((elapsedSeconds % 3600) / 60).floor();
        final seconds = (elapsedSeconds % 60);
        elapsedTime = '$hours:${minutes < 10 ? '0$minutes' : minutes}:${seconds < 10 ? '0$seconds' : seconds}';
      });
    });

    _scanFilesAndChangeIcons(directoryPath);
  }

  void stopScan() {
    // Stop the scan subscription and cancel the timer
    scanSubscription.cancel();
    scanTimer.cancel();

    // Update UI to reflect scan stopped
    setState(() {
      isScanRunning = false;
      iconData = Icons.check;
      buttonText = 'DISABLE';
      buttonColor = Colors.red;
      iconColor = Colors.green;
    });
  }

  void handleScanButtonPressed() async {
    if (isScanRunning) {
      // User pressed stop button
      stopScan();
    } else {
      // User pressed start button
      directoryPath = await selectDirectory();

      if (directoryPath != null) {
        startScan(directoryPath!);
      } else {
        // User cancelled directory selection
        print('Directory selection canceled.');
      }
    }
  }

  Future<String?> selectDirectory() async {
    final result = await FilePicker.platform.getDirectoryPath();
    return result;
  }
}
