## Android Device Manager

This project offers a web application, Android Device Manager, designed to simplify Android device and emulator management for security researchers and developers. It streamlines the process of identifying vulnerabilities within Android apps, the Android system itself, and the underlying Android (Linux) core. The tool leverages the Android Debug Bridge (adb) for device interaction and provides a range of features to enhance efficiency and effectiveness in Android security research.

## Features

* **Device Management:** Gain a comprehensive overview of all connected Android devices and emulators with detailed information displayed on a single web page.
* **Remote Access:** Interact directly with the adb shell of selected devices from the web interface itself.
* **Screen Viewing:** Integrate tools like "scrcpy" or establish a VNC connection to remotely view the screen of connected devices.
* **Access Control:** Implement user login functionalities to manage access to devices and prevent simultaneous usage by multiple users.
* **File System Exploration:** Explore the entire file system of rooted physical devices and emulators for deeper analysis.
* **App Management:** View a list of all installed applications on the selected device for in-depth examination.
* **Network Traffic Inspection:** Monitor, trace, and log HTTP/S traffic, aiding in security assessments by analyzing network data to and from the device.

## Installation (**Note:** Placeholder instructions)

1. Clone the repository using the following command:

   ```bash
   git clone https://github.com/gohilmukund123/android-device-manager.git
   ```

2. Navigate to the project directory:

   ```bash
   cd android-device-manager
   ```

3. Install required dependencies:

   ```bash
   npm install
   ```

4. Start the development server:

   ```bash
   npm start
   ```

5. Access the application in your web browser at `http://localhost:8888`.

## Tech Stack

* **Backend:** Python (for adb functionality)
* **Frontend:** HTML/CSS (for design and layout)
* **Frontend Framework:** React (for building user interfaces)
* **Client-side Scripting:** JavaScript (for dynamic interactions)

## Testing

To guarantee the effectiveness of Android Device Manager, comprehensive testing will be conducted with a focus on:

* **Multi-Device Handling:** Verify smooth operation with multiple Android devices and emulators connected to the server simultaneously.
* **Feature Functionality:** Ensure all implemented features function as intended.

## Screenshots
**List of Connected Devices:**
![a1](https://github.com/gohilmukund123/Android-Device-Manager/assets/114324098/d7544253-5604-4335-95bf-eac57769d2ed)

**ADB Shell Access:**
![a2](https://github.com/gohilmukund123/Android-Device-Manager/assets/114324098/b5771cd7-7e4b-4c28-a154-bfe0cc1454be)

**Screen Mirroring using SCRCPY:**
![a3](https://github.com/gohilmukund123/Android-Device-Manager/assets/114324098/58d9d062-e1c2-4145-963c-894bed25e5b0)

**Package inspection:**
![a4](https://github.com/gohilmukund123/Android-Device-Manager/assets/114324098/dce47338-2fd6-4db1-8ed1-9522cd666642)

**ADB Shell Command Execution(Single Line Commands):**
![a5](https://github.com/gohilmukund123/Android-Device-Manager/assets/114324098/50d49c83-46be-4a4b-a701-6e9ec350b61a)

**Reboot Mobile Device using ABD Shell Commands:**
![a6](https://github.com/gohilmukund123/Android-Device-Manager/assets/114324098/46e8fe06-26f8-4fbe-a875-9557d67d093e)
