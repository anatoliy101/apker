import subprocess
import shutil
import os
import sys
import tempfile
import argparse
import re
import random
import string
from zipfile import ZipFile, ZipInfo

def get_package_name(apk_path):
    # Determine the command for apkanalyzer based on the OS
    apkanalyzer_cmd = "apkanalyzer.bat" if os.name == 'nt' else "apkanalyzer"

    try:
        cmd = [apkanalyzer_cmd, "manifest", "print", apk_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout

        # Parse the XML output to get the package name
        match = re.search(r'package="([^"]+)"', output)
        if match:
            package_name = match.group(1)
            return package_name
        else:
            print(f"[ERROR] Failed to extract package name using apkanalyzer.")
            sys.exit(1)
    except FileNotFoundError as e:
        print(f"[ERROR] The command '{e.filename}' was not found. Please ensure apkanalyzer is installed and added to your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to run apkanalyzer: {e}")
        print(f"[ERROR] apkanalyzer stderr: {e.stderr}")
        sys.exit(1)

def validate_apk(apk_path):
    print("\n" + "-" * 60)
    print("🔍 Validating APK with apkanalyzer")
    print("-" * 60)
    apkanalyzer_cmd = "apkanalyzer.bat" if os.name == 'nt' else "apkanalyzer"

    try:
        cmd = [apkanalyzer_cmd, "apk", "summary", apk_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[INFO] APK summary:\n{result.stdout}")
        print(f"[INFO] APK validation passed.")
        print("-" * 60)
        return True
    except FileNotFoundError as e:
        print(f"[ERROR] The command '{e.filename}' was not found. Please ensure apkanalyzer is installed and added to your PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to validate APK with apkanalyzer: {e}")
        print(f"[ERROR] apkanalyzer stderr: {e.stderr}")
        print(f"[ERROR] APK validation failed.")
        print("-" * 60)
        return False

def process_apk(apk_path, manifest_path, temp_dir, save_logs):
    print("\n" + "-" * 60)
    print("🔧 Step 1: Replacing AndroidManifest.xml in Memory")
    print("-" * 60)

    # Read the new AndroidManifest.xml into memory
    with open(manifest_path, 'rb') as f:
        new_manifest_data = f.read()

    # Dictionary to store APK file data in memory
    file_contents = {}
    log_entries = []

    # Read the APK content
    try:
        with ZipFile(apk_path, 'r') as zip_ref:
            print(f"[INFO] Reading APK contents into memory...")
            for zip_info in zip_ref.infolist():
                filename = zip_info.filename
                compress_type = zip_info.compress_type
                # Read file data
                data = zip_ref.read(zip_info)
                # If it's AndroidManifest.xml, replace the data
                if filename == 'AndroidManifest.xml':
                    data = new_manifest_data
                    print(f"[INFO] AndroidManifest.xml successfully replaced.")
                # Store data and compression type
                file_contents[filename] = (data, compress_type)
                # For logging
                log_entries.append((filename, compress_type))
            print(f"[INFO] APK contents read into memory.")
    except Exception as e:
        print(f"[ERROR] Failed to read APK: {e}")
        sys.exit(1)

    # Save logs if required
    if save_logs:
        try:
            log_file_path = 'unpack_log.txt'
            with open(log_file_path, 'w') as log_file:
                for filename, compress_type in log_entries:
                    log_file.write(f"File Name: {filename}, Compression Type: {compress_type}\n")
            print(f"[INFO] Logs saved to {log_file_path}")
        except Exception as e:
            print(f"[ERROR] Failed to save logs: {e}")
            sys.exit(1)

    # Reassemble the APK from in-memory data
    apk_temp_path = os.path.join(temp_dir, 'app.apk')
    try:
        with ZipFile(apk_temp_path, 'w') as zip_out:
            for filename, (data, compress_type) in file_contents.items():
                zip_info = ZipInfo(filename=filename)
                zip_info.compress_type = compress_type
                zip_out.writestr(zip_info, data)
        print(f"[INFO] APK successfully reassembled with original filenames and compression methods.")
    except Exception as e:
        print(f"[ERROR] Failed to reassemble APK: {e}")
        sys.exit(1)

    print("-" * 60)
    return apk_temp_path

def zipalign_apk(apk_path, temp_dir):
    print("\n" + "-" * 60)
    print("📐 Step 2: Aligning APK (zipalign)")
    print("-" * 60)
    zipalign_cmd = "zipalign.exe" if os.name == 'nt' else "zipalign"

    aligned_apk_path = os.path.join(temp_dir, 'app_aligned.apk')
    cmd = [zipalign_cmd, '-p', '-f', '-v',  '4', apk_path, aligned_apk_path]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[INFO] APK aligned successfully.")
    except FileNotFoundError as e:
        print(f"[ERROR] The command '{e.filename}' was not found. Please ensure zipalign is installed and added to your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to align APK: {e}")
        print(f"[ERROR] zipalign stderr: {e.stderr}")
        sys.exit(1)

    print("-" * 60)
    return aligned_apk_path

def sign_apk(apk_path, package_name, save_keystore, temp_dir):
    print("\n" + "-" * 60)
    print("🔑 Step 3: Signing APK")
    print("-" * 60)
    # Generate random data for passwords
    store_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
    key_password = store_password  # Key password must be the same as store password for PKCS12

    key_alias = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

    # Print the passwords and key alias
    print(f"[INFO] Key Alias: {key_alias}")
    print(f"[INFO] Store Password: {store_password}")
    print(f"[INFO] Key Password: {key_password}")

    # Determine the command for apksigner based on the OS
    apksigner_cmd = "apksigner.bat" if os.name == 'nt' else "apksigner"

    keystore_filename = f"keystore_{package_name}.p12"
    keystore_temp_path = os.path.join(temp_dir, keystore_filename)

    # Generate the keystore in the temporary directory
    try:
        subprocess.run([
            "keytool", "-genkeypair", "-v",
            "-keystore", keystore_temp_path,
            "-storetype", "PKCS12",
            "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000",
            "-alias", key_alias,
            "-dname", "CN=apker, OU=apker, O=apker, L=City, S=State, C=US",
            "-storepass", store_password,
            "-keypass", key_password  # Same as store_password
        ], check=True, capture_output=True, text=True)
        print(f"[INFO] Keystore generated at temporary location.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to generate keystore: {e}")
        print(f"[ERROR] keytool output: {e.stderr}")
        sys.exit(1)

    signed_apk_path = os.path.join(temp_dir, 'app_signed.apk')

    # Sign the APK
    cmd = [
        apksigner_cmd, "sign",
        "--ks", keystore_temp_path,
        "--ks-key-alias", key_alias,
        "--ks-pass", f"pass:{store_password}",
        "--key-pass", f"pass:{key_password}",  # Same password
        "--out", signed_apk_path,
        apk_path
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[INFO] APK signed successfully.")
    except FileNotFoundError as e:
        print(f"[ERROR] The command '{e.filename}' was not found. Please ensure it is installed and added to your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to sign APK: {e}")
        print(f"[ERROR] apksigner stderr: {e.stderr}")
        sys.exit(1)

    # If --save-keystore is specified, move the keystore to the APK directory
    if save_keystore:
        apk_dir = os.path.dirname(apk_path)
        keystore_final_path = os.path.join(apk_dir, keystore_filename)
        shutil.move(keystore_temp_path, keystore_final_path)
        print(f"[INFO] Keystore saved as: {keystore_final_path}")
    else:
        print(f"[INFO] Keystore not saved (temporary keystore used).")

    print("-" * 60)
    return signed_apk_path

def install_apk(apk_path):
    print("\n" + "-" * 60)
    print("📲 Installing APK on Device")
    print("-" * 60)
    try:
        cmd = ["adb", "install", "-r", apk_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if "Success" in result.stdout:
            print(f"[INFO] APK installation succeeded.")
            print("-" * 60)
            return True
        else:
            print(f"[ERROR] APK installation failed:\n{result.stdout}")
            return False
    except FileNotFoundError as e:
        print(f"[ERROR] The command '{e.filename}' was not found. Please ensure adb is installed and added to your PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to install APK: {e}")
        print(f"[ERROR] adb stderr: {e.stderr}")
        return False

def uninstall_apk(package_name):
    print("\n" + "-" * 60)
    print("🗑️  Uninstalling APK from Device")
    print("-" * 60)
    try:
        cmd = ["adb", "uninstall", package_name]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if "Success" in result.stdout:
            print(f"[INFO] APK uninstallation succeeded.")
            print("-" * 60)
            return True
        else:
            print(f"[ERROR] APK uninstallation failed:\n{result.stdout}")
            return False
    except FileNotFoundError as e:
        print(f"[ERROR] The command '{e.filename}' was not found. Please ensure adb is installed and added to your PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to uninstall APK: {e}")
        print(f"[ERROR] adb stderr: {e.stderr}")
        return False

def main():
    print("=" * 60)
    print("🚀 APK Processing Script Started")
    print("=" * 60)
    try:
        parser = argparse.ArgumentParser(description='APK Processing Script')
        parser.add_argument('apk_path', help='Path to the input APK file')
        parser.add_argument('manifest_path', help='Path to the AndroidManifest.xml file')
        parser.add_argument('--save-keystore', '-s', action='store_true', help='Save the keystore with the name keystore_package_name.p12')
        parser.add_argument('--save-logs', '-l', action='store_true', help='Save logs during unpacking and assigning temporary filenames')
        args = parser.parse_args()

        apk_path = args.apk_path
        manifest_path = args.manifest_path
        save_keystore = args.save_keystore
        save_logs = args.save_logs

        print(f"[INFO] APK Path: {apk_path}")
        print(f"[INFO] AndroidManifest Path: {manifest_path}")
        print(f"[INFO] Save Keystore: {'Yes' if save_keystore else 'No'}")
        print(f"[INFO] Save Logs: {'Yes' if save_logs else 'No'}")

        # Extract package name from the original APK using apkanalyzer
        package_name = get_package_name(apk_path)
        if not package_name:
            print(f"[ERROR] Failed to extract package name from APK.")
            sys.exit(1)
        print(f"[INFO] Package Name: {package_name}")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Process APK: replace manifest
            processed_apk_path = process_apk(apk_path, manifest_path, temp_dir, save_logs)

            # Validate APK after processing
            is_valid = validate_apk(processed_apk_path)

            if not is_valid:
                print(f"[WARNING] APK validation failed after processing.")
                # Try to install and uninstall the unaligned and unsigned APK
                installed = install_apk(processed_apk_path)
                install_status = "Success" if installed else "Failed"
                if installed:
                    uninstalled = uninstall_apk(package_name)
                    uninstall_status = "Success" if uninstalled else "Failed"
                else:
                    uninstall_status = "N/A"
            else:
                print(f"[INFO] APK validation passed after processing.")
                # Zipalign APK
                aligned_apk_path = zipalign_apk(processed_apk_path, temp_dir)

                # Sign APK
                signed_apk_path = sign_apk(aligned_apk_path, package_name, save_keystore, temp_dir)

                # Copy final APK to the original APK directory with '_updated.apk' suffix
                apk_dir = os.path.dirname(apk_path)
                apk_basename = os.path.basename(apk_path)
                updated_apk_name = apk_basename.replace(".apk", "_updated.apk")
                updated_apk_path = os.path.join(apk_dir, updated_apk_name)
                shutil.copy(signed_apk_path, updated_apk_path)
                print(f"[INFO] Final APK saved at {updated_apk_path}")

                # Proceed to installation and uninstallation
                installed = install_apk(updated_apk_path)
                install_status = "Success" if installed else "Failed"
                if installed:
                    uninstalled = uninstall_apk(package_name)
                    uninstall_status = "Success" if uninstalled else "Failed"
                else:
                    uninstall_status = "N/A"

        print("\n" + "=" * 60)
        print("📄 Summary")
        print("=" * 60)
        print(f"[INFO] Input APK: {apk_path}")
        print(f"[INFO] Input AndroidManifest: {manifest_path}")
        if is_valid:
            print(f"[INFO] Updated APK: {updated_apk_path}")
        else:
            print(f"[INFO] Processed APK (not updated): {processed_apk_path}")
        print(f"[INFO] APK Validation: {'Passed' if is_valid else 'Failed'}")
        print(f"[INFO] Installation: {install_status}")
        print(f"[INFO] Uninstallation: {uninstall_status}")
        if save_keystore and is_valid:
            keystore_filename = f"keystore_{package_name}.p12"
            keystore_final_path = os.path.join(apk_dir, keystore_filename)
            print(f"[INFO] Keystore saved as: {keystore_final_path}")
        if save_logs:
            log_file_path = 'unpack_log.txt'
            print(f"[INFO] Unpack logs saved at: {log_file_path}")
        print("=" * 60)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()