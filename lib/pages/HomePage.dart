import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';
import 'dart:io' show Directory, FileSystemCreateEvent, FileSystemEvent, Platform, Process;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:http/http.dart' as http; // Import http package

class HomePage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color.fromARGB(98, 90, 86, 86),
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
  String? monitoredDirectory;
  StreamSubscription<FileSystemEvent>? _monitorSubscription;
  final TextEditingController phoneController = TextEditingController();
  String phoneNumberError = '';

  @override
  void initState() {
    super.initState();
    _loadMonitoredDirectory(); // Load the monitored directory on initialization
  }

  @override
  void dispose() {
    _monitorSubscription?.cancel(); // Cancel subscription when disposing
    super.dispose();
  }

  void _loadMonitoredDirectory() async {
    final prefs = await SharedPreferences.getInstance();
    monitoredDirectory = prefs.getString('monitoredDirectory'); // Retrieve the saved directory

    if (monitoredDirectory != null) {
      _startMonitoring(monitoredDirectory!); // Start monitoring if the directory is available
    }
  }

  void _startMonitoring(String directoryPath) {
    _monitorSubscription?.cancel(); // Cancel any existing subscription

    final directory = Directory(directoryPath);
    if (!directory.existsSync()) {
      print('Directory does not exist: $directoryPath');
      return;
    }

    _monitorSubscription = directory.watch(recursive: true).listen(
      (FileSystemEvent event) {
        if (event is FileSystemCreateEvent) {
          print('New file detected: ${event.path}'); // Log the file detection
          _scanFile(event.path); // Scan the new file
        }
      },
      onError: (error) => print('Error monitoring directory: $error'),
      onDone: () => print('Monitoring ended.'),
    );
  }

  void _scanFile(String filePath) async {
    final pythonScript = 'flask_api/script/app.py'; // Path to your Python script

    try {
      print('Scanning: $filePath'); // Debug message to indicate scanning
      final result = await Process.run('python3', [pythonScript, filePath]);

      if (result.exitCode == 0) {

        
        final output = result.stdout.toString().trim(); // Get script output

        print('File scanned successfully: $output');

        if (output == "Malware") {
          // Send SMS if malware is detected
          final message = "Alert! Malware has been detected in: $filePath"; // SMS content
          _showMalwareAlert(context, filePath); // Show the alert dialog
          // _sendSmsNotification(message);
        }
      } else {
        print('File scan failed: ${result.stderr}'); // Handle failure
      }
    } catch (e) {
      print('Error scanning file: $e'); // Handle exceptions
    }
  }

  void _showMalwareAlert(BuildContext context, String filePath) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text("Malware Detected"),
          content: Text("Malware has been detected in the following file: $filePath"),
          actions: [
            TextButton(
              onPressed: () {
                Navigator.of(context).pop(); // Close the dialog
              },
              child: Text("OK"),
            ),
            ElevatedButton(
              onPressed: () {
                _openContainingFolder(filePath); // Open the containing directory
                Navigator.of(context).pop(); // Close the dialog after action
              },
              child: Text("Open Directory"),
            ),
          ],
        );
      },
    );
  }

  void _openContainingFolder(String filePath) {
    final directory = Directory(filePath).parent.path; // Get the containing directory
    if (Platform.isWindows) {
      Process.start("explorer.exe", [directory]); // Open in Windows Explorer
    } else if (Platform.isMacOS) {
      Process.start("open", [directory]); // Open in Finder (MacOS)
    } else if (Platform.isLinux) {
      Process.start("xdg-open", [directory]); // Open in file manager (Linux)
    }
  }

  Future<void> _sendSmsNotification(String message) async {
    print('300');
    final apiKey = "41b35041";
    final apiSecret = "8KleUiYbk2S77WUp";
    final from = "Bastion"; // Sender name or number
    final to = phoneController.text; // Recipient's phone number

    final response = await http.post(
      Uri.parse("https://rest.nexmo.com/sms/json"),
      headers: {
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        "api_key": apiKey,
        "api_secret": apiSecret,
        "from": from,
        "to": to,
        "text": message,
      }),
    );

    if (response.statusCode == 200) {
      print('400');
      final responseData = jsonDecode(response.body);
      final messageStatus = responseData["messages"][0]["status"];

      if (messageStatus == "0") {
        print("SMS sent successfully");
      } else {
        print("Failed to send SMS: ${responseData['messages'][0]['error-text']}");
      }
    } else {
      print("Failed to send SMS. Status code: ${response.statusCode}");
    }
  }

  void _showSettingsDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text("Configure Phone Number"),
          content: Container(
            width: 300,
            height: 150,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Enter Phone Number',
                  style: TextStyle(fontSize: 15),
                ),
                
                TextField(
                  controller: phoneController,
                  decoration: InputDecoration(
                    hintText: '63',
                    errorText: phoneNumberError.isEmpty ? null : phoneNumberError,
                  ),
                  keyboardType: TextInputType.phone,
                  inputFormatters: [
                    FilteringTextInputFormatter.allow(RegExp(r'^[+0-9]*$')),
                  ],
                  onChanged: (value) {
                    if (value.length == 12) {
                      phoneNumberError = '';
                    } else {
                      phoneNumberError = 'Phone number must start with 63';
                    }
                  },
                ),
              ],
            ),
          ),
          actions: [
            ElevatedButton(
              onPressed: () {
                if (phoneController.text.length == 12) {
                  Navigator.of(context).pop(); // Close the dialog
                  print(phoneController.text);
                } else {
                  print("Invalid phone number");
                }
              },
              child: const Text("Save"),
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: Container(
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
                  left: 105,
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
          child: Center( // Center the content horizontally
            child: Container(
              child: Column(
                mainAxisSize: MainAxisSize.min, // Center vertically within the parent
                children: [
                  if (monitoredDirectory != null) ...[
                    Text(
                      'Monitoring directory: $monitoredDirectory',
                      style: const TextStyle(
                        fontSize: 18,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(height: 10), // Add spacing between text and button
                  ],
                  ElevatedButton(
                    onPressed: _selectDirectory, // Select a folder to monitor
                    style: ButtonStyle(
                      backgroundColor: MaterialStateProperty.all<Color>(Colors.green),
                      shape: MaterialStateProperty.all<RoundedRectangleBorder>(
                        RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                        ),
                      ),
                      minimumSize: MaterialStateProperty.all<Size>(const Size(250, 70)),
                    ),
                    child: const Text(
                      'Select Folder',
                      style: TextStyle(
                        color: Colors.black,
                        fontSize: 24,
                        fontWeight: FontWeight.normal,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
        Expanded(
          child: Container(
            alignment: Alignment.topRight,
            child: IconButton(
              icon: const Icon(
                Icons.settings,
                size: 40,
              ),
              onPressed: () => _showSettingsDialog(context), // Show the settings dialog
              color: Colors.white,
            ),
          ),
        ),
      ],
    );
  }

    Future<void> _selectDirectory() async {
    final selectedPath = await FilePicker.platform.getDirectoryPath();
    if (selectedPath != null) {
      setState(() {
        monitoredDirectory = selectedPath; // Save the monitored directory
        print('Directory selected: $selectedPath.');
      });
      _startMonitoring(selectedPath); // Start monitoring the directory
    } else {
      print('Directory selection canceled.');
    }
  }

}

void main() => runApp(MaterialApp(home: HomePage()));
