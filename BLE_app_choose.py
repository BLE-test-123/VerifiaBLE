import os
import shutil
from androguard.misc import AnalyzeAPK

def analyze_ble_apk(apk_path: str):
    try:
        # 分析APK文件
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print(f"无法分析APK文件 {apk_path}: {e}")
        return False

    # 扩展的BLE权限列表
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

    # 获取APK声明的所有权限
    permissions = a.get_permissions()

    # 检查是否声明了任何BLE相关权限
    ble_permissions_found = [perm for perm in permissions if perm in ble_permissions]

    # 扩展的BLE相关类列表
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

    # 扩展的与数据交换相关的方法名
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

    # 用于存储检测到的BLE API调用
    ble_api_calls = []

    # 遍历所有方法，检查是否使用了BLE相关的API
    for method in dx.get_methods():
        method_analysis = method
        class_name = method.class_name
        method_name = method.name

        code = method_analysis.get_method()
        if not code or not hasattr(code, 'get_instructions'):
            continue

        # 遍历方法的代码字符串
        for instruction in code.get_instructions():
            output = instruction.get_output()

            # 检查指令中是否包含BLE相关的类和方法
            if any(ble_class in output for ble_class in ble_classes) and any(
                    ble_method in output for ble_method in ble_methods):
                ble_api_calls.append((class_name, method_name, output))

    # 判断是否是BLE应用程序
    if ble_permissions_found and ble_api_calls:
        return True
    else:
        return False

def process_apks_in_folder(folder_path: str):
    # 创建存储BLE应用的文件夹
    ble_folder = os.path.join(folder_path, "BLE_filter")
    if not os.path.exists(ble_folder):
        os.makedirs(ble_folder)

    # 遍历文件夹中的所有APK文件
    for filename in os.listdir(folder_path):
        if filename.endswith(".apk"):
            apk_path = os.path.join(folder_path, filename)

            # 检查目标文件夹中是否已有该APK
            if filename in os.listdir(ble_folder):
                print(f"BLE_filter 文件夹中已存在 {filename}，跳过。")
                continue

            if analyze_ble_apk(apk_path):
                # 如果是BLE应用，将其移动到ble_filter文件夹
                destination_path = os.path.join(ble_folder, filename)
                shutil.move(apk_path, destination_path)
                print(f"检测到BLE应用并已移动：{filename}")
            else:
                print(f"非BLE应用：{filename}")

if __name__ == "__main__":
    folder_path = "/home/biwei/Desktop/data-rating2022/Androzoo/Benign/2022"  # 请替换为你的APK文件夹路径
    process_apks_in_folder(folder_path)
