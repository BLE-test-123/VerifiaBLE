import os
import shutil
from androguard.misc import AnalyzeAPK

def analyze_ble_apk(apk_path: str):
    try:
        # Analyze the APK file
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print(f"Failed to analyze APK file {apk_path}: {e}")
        return False

    # Extended BLE permissions list
    ble_permissions = [
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.BLUETOOTH_PRIVILEGED",
        "android.permission.BLUETOOTH_BACKGROUND"
    ]

    # Get all permissions declared in the APK
    permissions = a.get_permissions()

    # Check if any BLE-related permission is declared
    ble_permissions_found = [perm for perm in permissions if perm in ble_permissions]

    # Extended BLE-related class list
    ble_classes = [
        "Landroid/bluetooth/BluetoothAdapter;",
        "Landroid/bluetooth/BluetoothDevice;",
        "Landroid/bluetooth/BluetoothGatt;",
        "Landroid/bluetooth/BluetoothGattCallback;",
        "Landroid/bluetooth/BluetoothGattService;",
        "Landroid/bluetooth/BluetoothGattCharacteristic;",
        "Landroid/bluetooth/le/BluetoothLeScanner;",
        "Landroid/bluetooth/le/ScanCallback;",
        "Landroid/bluetooth/le/ScanResult;",
        "Landroid/bluetooth/le/ScanSettings;",
        "Landroid/bluetooth/le/AdvertiseCallback;",
        "Landroid/bluetooth/le/AdvertiseSettings;",
        "Landroid/bluetooth/le/AdvertiseData;",
        "Landroid/bluetooth/BluetoothManager;",
        "Landroid/bluetooth/BluetoothServerSocket;",
        "Landroid/bluetooth/BluetoothSocket;"
    ]

    # Extended BLE-related method names for data exchange
    ble_methods = [
        "connect",
        "disconnect",
        "readCharacteristic",
        "writeCharacteristic",
        "setCharacteristicNotification",
        "startScan",
        "stopScan",
        "startAdvertising",
        "stopAdvertising",
        "onConnectionStateChange",
        "onServicesDiscovered",
        "onCharacteristicRead",
        "onCharacteristicWrite",
        "onCharacteristicChanged",
        "listenUsingRfcommWithServiceRecord",
        "createRfcommSocketToServiceRecord",
        "getBluetoothLeScanner",
        "getBluetoothManager"
    ]

    # Used to store detected BLE API calls
    ble_api_calls = []

    # Traverse all methods to check for BLE-related API usage
    for method in dx.get_methods():
        method_analysis = method
        class_name = method.class_name
        method_name = method.name

        code = method_analysis.get_method()
        if not code or not hasattr(code, 'get_instructions'):
            continue

        # Traverse the code instructions of the method
        for instruction in code.get_instructions():
            output = instruction.get_output()

            # Check if BLE-related class and method are included in the instruction
            if any(ble_class in output for ble_class in ble_classes) and any(
                    ble_method in output for ble_method in ble_methods):
                ble_api_calls.append((class_name, method_name, output))

    # Determine if this is a BLE application
    if ble_permissions_found and ble_api_calls:
        return True
    else:
        return False

def process_apks_in_folder(folder_path: str):
    # Create a folder to store BLE applications
    ble_folder = os.path.join(folder_path, "BLE_filter")
    if not os.path.exists(ble_folder):
        os.makedirs(ble_folder)

    # Traverse all APK files in the folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".apk"):
            apk_path = os.path.join(folder_path, filename)

            # Check if the target folder already has this APK
            if filename in os.listdir(ble_folder):
                print(f"{filename} already exists in BLE_filter folder, skipping.")
                continue

            if analyze_ble_apk(apk_path):
                # If it's a BLE application, move it to ble_filter folder
                destination_path = os.path.join(ble_folder, filename)
                shutil.move(apk_path, destination_path)
                print(f"Detected BLE application and moved: {filename}")
            else:
                print(f"Not a BLE application: {filename}")

if __name__ == "__main__":
    folder_path = "<YOUR_FOLDER_PATH>"  # 👉 Replace with your APK folder path
    process_apks_in_folder(folder_path)
