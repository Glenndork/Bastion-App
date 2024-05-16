import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'dart:io' show Directory, File, FileMode, FileSystemCreateEvent, FileSystemEvent, Platform, Process;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:http/http.dart' as http; // Import http package
import 'package:synchronized/synchronized.dart';

class BaseApp extends StatelessWidget {
  const BaseApp({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color.fromARGB(98, 90, 86, 86),
      body: Container(
        child: const ThreeColumnsRow(),
      ),
    );
  }
}

class ThreeColumnsRow extends StatefulWidget {
  const ThreeColumnsRow({super.key});

  @override
  _ThreeColumnsRowState createState() => _ThreeColumnsRowState();
}

class _ThreeColumnsRowState extends State<ThreeColumnsRow> {
  String? monitoredDirectory;
  StreamSubscription<FileSystemEvent>? _monitorSubscription;
  final TextEditingController phoneController = TextEditingController();
  String phoneNumberError = '';
  bool _isMonitoring = false; // State variable for monitoring status
  late File _logFile;
  String? _currentFileBeingScanned; // State variable for the current file being scanned
  final _logLock = Lock();

  @override
  void initState() {
    super.initState();
    _initializeLogFile();
  }

  @override
  void dispose() {
    _monitorSubscription?.cancel(); // Cancel subscription when disposing
    super.dispose();
  }

  Future<void> _initializeLogFile() async {
    final directory = await getApplicationDocumentsDirectory();
    _logFile = File('${directory.path}/logfile.txt');
    
    print('Log file path: ${_logFile.path}'); // Print path for debugging
    
    if (!(await _logFile.exists())) {
      await _logFile.create();
    }
  }

  Future<void> _writeToLogFile(String message) async {
    final timestamp = DateTime.now().toIso8601String();
    final logMessage = '$timestamp: $message\n';
    try {
      await _logLock.synchronized(() async {
        await _logFile.writeAsString(logMessage, mode: FileMode.append, flush: true);
      });
    } catch (e) {
      print('Error writing to log file: $e');
    }
  }

  void _loadMonitoredDirectory() async {
    final prefs = await SharedPreferences.getInstance();
    monitoredDirectory = prefs.getString('monitoredDirectory'); // Retrieve the saved directory

    if (monitoredDirectory != null) {
      _startMonitoring(monitoredDirectory!); // Start monitoring if the directory is available
    }
  }

  void _startMonitoring(String directoryPath) {
    final directory = Directory(directoryPath);
    if (!directory.existsSync()) {
      print('Directory does not exist: $directoryPath');
      return;
    }

    setState(() {
      _isMonitoring = true; // Set monitoring status to true
    });

    _monitorSubscription = directory.watch(recursive: true).listen(
      (FileSystemEvent event) {
        if (event is FileSystemCreateEvent) {
          print('New file detected: ${event.path}');
          _scanFile(event.path);
        }
      },
      onError: (error) {
        print('Error monitoring directory: $error');
        setState(() {
          _isMonitoring = false; // Set monitoring status to false on error
        });
      },
      onDone: () {
        print('Monitoring ended.');
        setState(() {
          _isMonitoring = false; // Set monitoring status to false when done
        });
      },
    );
  }

void _scanFile(String filePath) async {
  final pythonAssetPath = 'assets/flask_api/script/app2.py';
  final modelAssetPath = 'assets/flask_api/models/version1.pkl';

  try {
    print('Scanning: $filePath'); // Debug message to indicate scanning
    setState(() {
      _currentFileBeingScanned = filePath; // Update the state with the current file being scanned
    });

    // Load the Python script from assets
    final pythonScript = await rootBundle.loadString(pythonAssetPath);

    // Load the model file from assets
    final modelData = await rootBundle.load(modelAssetPath);
    final modelBytes = modelData.buffer.asUint8List();

    // Save the script to a temporary file
    final tempDir = await getTemporaryDirectory();
    final tempScriptPath = '${tempDir.path}/app2.py';
    final tempScriptFile = File(tempScriptPath);
    await tempScriptFile.writeAsString(pythonScript);

    // Save the model to a temporary file
    final tempModelPath = '${tempDir.path}/version1.pkl';
    final tempModelFile = File(tempModelPath);
    await tempModelFile.writeAsBytes(modelBytes);

    // Check if the script and model were saved successfully
    if (!await tempScriptFile.exists() || !await tempModelFile.exists()) {
      print('Failed to save Python script or model to temporary directory');
      await _writeToLogFile('Failed to save Python script or model to temporary directory');
      return;
    }

    print('Python script saved to temporary path: $tempScriptPath'); // Log the script path
    print('Model saved to temporary path: $tempModelPath'); // Log the model path

    // Execute the Python script with the file path and model path as arguments
    final result = await Process.run('python3', [tempScriptPath, filePath, tempModelPath]);

    // Check the exit code
    if (result.exitCode == 0) {
      print('100');
      final output = result.stdout.toString().trim(); // Get script output
      print('$output');
      await _writeToLogFile('Scanned $filePath: $output'); // Log the scan result

      if (output.contains("Malware")) {
        // Malware detected actions
        final message = "Alert! Malware has been detected in: $filePath"; // SMS content
        await _writeToLogFile(message); // Log the malware detection
        _showMalwareAlert(context, filePath, output);
        _sendSmsNotification(message);
      }
    } else {
      print('File scan failed: ${result.stderr}'); // Handle failure
      await _writeToLogFile('Failed to scan $filePath: ${result.stderr}'); // Log the failure
    }
  } catch (e) {
    print('Error scanning file: $e'); // Handle exceptions
    await _writeToLogFile('Error scanning $filePath: $e'); // Log the error
  } finally {
    setState(() {
      _currentFileBeingScanned = null; // Reset the current file being scanned after scanning
    });
  }
}

  void _showMalwareAlert(BuildContext context, String filePath, String output) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text("Malware Detected"),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text("Malware has been detected in the following file: $filePath"),
              const SizedBox(height: 10),
              Text(output, style: const TextStyle(color: Colors.red)),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () {
                Navigator.of(context).pop(); // Close the dialog
              },
              child: const Text("OK"),
            ),
            ElevatedButton(
              onPressed: () {
                _openContainingFolder(filePath); // Open the containing directory
                Navigator.of(context).pop(); // Close the dialog after action
              },
              child: const Text("Open Directory"),
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

  void _scanDirectory(String directoryPath) async {
    final directory = Directory(directoryPath);
    if (!directory.existsSync()) {
      print('Directory does not exist: $directoryPath');
      return;
    }

    await for (final entity in directory.list(recursive: true)) {
      if (entity is File && entity.path.toLowerCase().endsWith('.exe')) {
        _scanFile(entity.path); // Scan the exe file
      }
    }
  }

  Future<void> _sendSmsNotification(String message) async {
    const apiKey = "176f54f4";
    const apiSecret = "voFzIJZIsxFXV5vc";
    const from = "Bastion"; // Sender name or number
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
    print("Sending SMS");
    if (response.statusCode == 200) {
      print("Processing");

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

  void _openLogFile() async {
    final directory = await getApplicationDocumentsDirectory();
    final logFilePath = '${directory.path}/logfile.txt';
    final logFile = File(logFilePath);

    if (await logFile.exists()) {
      if (Platform.isWindows) {
        await Process.run('notepad.exe', [logFilePath]);
      } else if (Platform.isMacOS) {
        await Process.run('open', ['-a', 'TextEdit', logFilePath]);
      } else if (Platform.isLinux) {
        await Process.run('xdg-open', [logFilePath]);
      }
    } else {
      print('Log file does not exist.');
    }
}

  void _showSettingsDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text("Configure Phone Number"),
          content: SizedBox(
            width: 300,
            height: 200, // Increase height to accommodate the new button
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const SizedBox(height: 20),
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
                const SizedBox(height: 30),
                ElevatedButton(
                  onPressed: _openLogFile,
                  child: const Text("See Logs"),
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
                    const SizedBox(height: 30),
                    if (_isMonitoring) ...[
                      const CircularProgressIndicator(
                        color: Colors.white,
                      ),
                      const SizedBox(height: 10),
                      if (_currentFileBeingScanned != null)
                        Text(
                          'Scanning: $_currentFileBeingScanned',
                          style: const TextStyle(
                            fontSize: 16,
                            color: Colors.white,
                          ),
                        ),
                    ],
                  ],
                  const SizedBox(height: 30),
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
                      'Select Directory',
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

  void _selectDirectory() async {
    final selectedPath = await FilePicker.platform.getDirectoryPath();
    if (selectedPath != null) {
      setState(() {
        monitoredDirectory = selectedPath; // Save the monitored directory
        print('Directory selected: $selectedPath.');
      });
      _startMonitoring(selectedPath); // Start monitoring the directory
      _scanDirectory(selectedPath); // Scan all exe files in the directory
    } else {
      print('Directory selection canceled.');
    }
  }
}

void main() => runApp(const MaterialApp(home: BaseApp()));
