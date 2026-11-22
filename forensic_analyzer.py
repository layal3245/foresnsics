import os
import json
import re
from datetime import datetime, timezone
from Registry import Registry

EVIDENCE_DIR = "evidence"
OUTPUT_DIR = "output"

HIVE_FILES = {
    "SAM": "77416-SAM",
    "SYSTEM": "77434-SYSTEM",
    "SOFTWARE": "77428-SOFTWARE",
    "SECURITY": "77422-SECURITY",
    "DEFAULT": "77389-DEFAULT",
    "NTUSER": "13977-NTUSER.DAT",
}

OPTIONAL_FILES = {
    "RecentFileCache": "32080-RecentFileCache.bcf",
    "AEINV_PREVIOUS": "32078-AEINV_PREVIOUS.xml",
}

results = {
    "investigation": {
        "tool": "Python Forensic Analyzer",
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_directory": EVIDENCE_DIR,
    },
    "system_information": {},
    "installed_applications": [],
    "user_accounts": [],
    "usb_history": [],
    "mounted_devices": {},
    "user_activity": [],
    "command_history": [],
    "browser_evidence": [],
    "application_compatibility": [],
    "missing_artifacts": [],
    "analysis_errors": [],
}




def evidence_path(filename):
    return os.path.join(EVIDENCE_DIR, filename)


def open_hive(filename):
    path = evidence_path(filename)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Evidence file not found: {path}")
    return Registry.Registry(path)


def read_value(key, value_name, default=None):
    try:
        return key.value(value_name).value()
    except Exception:
        return default


def readable_value(value):
    if value is None:
        return "Not available"
    if isinstance(value, bytes):
        for encoding in ("utf-16le", "utf-8", "ascii"):
            try:
                text = value.decode(encoding).replace("\x00", "").strip()
                if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text):
                    return text
            except (UnicodeDecodeError, ValueError):
                continue
        return f"[Binary data: {len(value)} bytes]"
    return str(value)


def record_error(section, error):
    message = f"{section}: {error}"
    results["analysis_errors"].append(message)
    print(f"[-] {message}")


def extract_utf16_strings(data, minimum_length=3):
    if not isinstance(data, bytes):
        return []

    decoded = data.decode("utf-16le", errors="ignore")
    found = []
    for part in decoded.split("\x00"):
        item = part.strip()
        if len(item) >= minimum_length and all(ch.isprintable() for ch in item):
            if item not in found:
                found.append(item)
    return found


def print_section(title):
    print(f"\n{'=' * 58}\n{title}\n{'=' * 58}")


def check_evidence():
    print_section("EVIDENCE FILE CHECK")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for filename in HIVE_FILES.values():
        if os.path.isfile(evidence_path(filename)):
            print(f"[+] Found: {filename}")
        else:
            print(f"[-] Missing: {filename}")
            results["missing_artifacts"].append(filename)

    for filename in OPTIONAL_FILES.values():
        if os.path.isfile(evidence_path(filename)):
            print(f"[+] Found: {filename}")
        else:
            print(f"[-] Optional artefact unavailable: {filename}")
            results["missing_artifacts"].append(filename)



def analyzer_software():
    print_section("OPERATING SYSTEM INFORMATION")
    try:
        reg = open_hive(HIVE_FILES["SOFTWARE"])
        key = reg.open(r"Microsoft\Windows NT\CurrentVersion")

        value_names = {
            "product_name": "ProductName",
            "display_version": "DisplayVersion",
            "current_build": "CurrentBuild",
            "current_build_number": "CurrentBuildNumber",
            "registered_owner": "RegisteredOwner",
            "registered_organization": "RegisteredOrganization",
            "service_pack": "CSDVersion",
        }

        for result_name, registry_name in value_names.items():
            value = read_value(key, registry_name)
            if value is not None:
                results["system_information"][result_name] = readable_value(value)
                print(f"[+] {registry_name}: {readable_value(value)}")
    except Exception as error:
        record_error("SOFTWARE hive analysis", error)



def analyze_sam():
    print_section("LOCAL WINDOWS USER ACCOUNTS")
    try:
        reg = open_hive(HIVE_FILES["SAM"])
        users_key = reg.open(r"SAM\Domains\Account\Users")

        rid_entries = [
            subkey.name()
            for subkey in users_key.subkeys()
            if subkey.name().lower() != "names"
        ]
        names_key = users_key.subkey("Names")
        usernames = sorted(user.name() for user in names_key.subkeys())

        for rid in sorted(rid_entries):
            results["user_accounts"].append({"type": "RID", "value": rid})

        for username in usernames:
            results["user_accounts"].append({"type": "Username", "value": username})
            print(f"[+] Username: {username}")

        print(f"[+] Usernames found: {len(usernames)}")
        print(f"[+] RID entries found: {len(rid_entries)}")
    except Exception as error:
        record_error("SAM hive analysis", error)


def analyze_ntuser():
    print_section("END-USER ACTIVITY (NTUSER.DAT)")

    rot13_table = str.maketrans(
        "abcdefghijklmnopqrstuvwxyz",
        "nopqrstuvwxyzabcdefghijklm"
    )

    registry_paths = {
        "RecentDocs": r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "RunMRU": r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "TypedPaths": r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "UserAssist": r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        "MountPoints2": r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
    }

   
    useful_extensions = (
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
        ".zip", ".rar", ".txt", ".jpg", ".jpeg", ".png", ".lnk",
        ".exe", ".msi", ".xps"
    )

    def clean_recent_item(text):
        text = str(text).strip().strip("\x00")
        if not text or not any(ch.isalnum() for ch in text):
            return None
        if not all(ch.isprintable() for ch in text):
            return None
        if any("\u4e00" <= ch <= "\u9fff" for ch in text):
            return None
        if text.casefold().endswith(useful_extensions):
            return text
        return None

    try:
        reg = open_hive(HIVE_FILES["NTUSER"])

     
        try:
            recent_key = reg.open(registry_paths["RecentDocs"])
            print("\n[Recent documents]")
            recent_items = []
            for value in recent_key.values():
                if value.name().casefold() == "mrulistex":
                    continue
                raw = value.value()
                candidates = extract_utf16_strings(raw) if isinstance(raw, bytes) else [readable_value(raw)]
                for candidate in candidates:
                    filename = clean_recent_item(candidate)
                    if filename and filename not in recent_items:
                        recent_items.append(filename)

            for filename in recent_items:
                entry = {"source": "RecentDocs", "filename": filename}
                results["user_activity"].append(entry)
                print(f"[+] {filename}")
            print(f"[+] Readable recent-document names: {len(recent_items)}")
        except Exception as error:
            print(f"[-] RecentDocs unavailable: {error}")

        
        try:
            run_key = reg.open(registry_paths["RunMRU"])
            print("\n[Run dialog history]")
            run_items = []
            for value in run_key.values():
                if value.name().casefold() == "mrulist":
                    continue
                raw = value.value()
                text = readable_value(raw)
                if isinstance(raw, bytes):
                    strings = extract_utf16_strings(raw)
                    text = strings[0] if strings else None
                if text and text != "Not available":
                    text = str(text).removesuffix("\\1").strip()
                    if text and text not in run_items:
                        run_items.append(text)
                        entry = {"source": "RunMRU", "name": value.name(), "value": text}
                        results["user_activity"].append(entry)
                        results["command_history"].append(entry.copy())
                        print(f"[+] {text}")
            print(f"[+] Run history entries: {len(run_items)}")
        except Exception as error:
            print(f"[-] RunMRU unavailable: {error}")

       
        try:
            typed_key = reg.open(registry_paths["TypedPaths"])
            print("\n[Typed paths]")
            typed_items = []
            for value in typed_key.values():
                raw = value.value()
                text = readable_value(raw)
                if isinstance(raw, bytes):
                    strings = extract_utf16_strings(raw)
                    text = strings[0] if strings else None
                if text and text != "Not available":
                    typed_items.append(text)
                    results["user_activity"].append({
                        "source": "TypedPaths", "name": value.name(), "value": text
                    })
                    print(f"[+] {text}")
            if not typed_items:
                print("[+] No readable typed paths recorded.")
        except Exception as error:
            print(f"[-] TypedPaths unavailable: {error}")

       
        try:
            userassist_key = reg.open(registry_paths["UserAssist"])
            applications = []
            for guid_key in userassist_key.subkeys():
                try:
                    count_key = guid_key.subkey("Count")
                except Exception:
                    continue
                for value in count_key.values():
                    decoded_name = value.name().translate(rot13_table)
                    if (decoded_name and all(ch.isprintable() for ch in decoded_name)
                            and len(decoded_name) > 2
                            and not any("\u4e00" <= ch <= "\u9fff" for ch in decoded_name)):
                        if decoded_name not in applications:
                            applications.append(decoded_name)
            print("\n[Application activity]")
            for application in applications:
                results["user_activity"].append({
                    "source": "UserAssist", "application": application
                })
            for application in applications[:10]:
                print(f"[+] {application}")
            print(f"[+] Readable application entries: {len(applications)}")
            if len(applications) > 10:
                print(f"[+] {len(applications) - 10} additional entries retained in JSON.")
        except Exception as error:
            print(f"[-] UserAssist unavailable: {error}")

        
        try:
            mount_key = reg.open(registry_paths["MountPoints2"])
            mount_points = []
            for subkey in mount_key.subkeys():
                name = subkey.name()
                if name.startswith("##") or re.match(r"^[A-Za-z]:$", name) or name.startswith("{"):
                    mount_points.append(name)
            print("\n[Mounted locations]")
            for mount_point in mount_points:
                results["user_activity"].append({
                    "source": "MountPoints2", "mount_point": mount_point
                })
                print(f"[+] {mount_point}")
            if not mount_points:
                print("[+] No readable mounted locations recorded.")
        except Exception as error:
            print(f"[-] MountPoints2 unavailable: {error}")

    except Exception as error:
        record_error("NTUSER.DAT analysis", error)


def analyze_system():
    print_section("SYSTEM CONFIGURATION AND USB HISTORY")
    try:
        reg = open_hive(HIVE_FILES["SYSTEM"])

        select_key = reg.open("Select")
        current = read_value(select_key, "Current")
        if current is None:
            raise ValueError("SYSTEM\\Select\\Current was not available")

        control_set = f"ControlSet{int(current):03d}"
        results["system_information"]["active_control_set"] = control_set

        try:
            computer_key = reg.open(
                rf"{control_set}\Control\ComputerName\ComputerName"
            )
            computer_name = read_value(computer_key, "ComputerName")
            if computer_name is not None:
                results["system_information"]["computer_name"] = readable_value(computer_name)
        except Exception:
            pass

        try:
            timezone_key = reg.open(rf"{control_set}\Control\TimeZoneInformation")
            for name in ("TimeZoneKeyName", "Bias"):
                value = read_value(timezone_key, name)
                if value is not None:
                    results["system_information"][name] = readable_value(value)
        except Exception:
            pass

        print(f"[+] Computer: {results['system_information'].get('computer_name', 'Not available')}")
        print(f"[+] Active control set: {control_set}")
        print(f"[+] Time zone: {results['system_information'].get('TimeZoneKeyName', 'Not available')}")
        if "Bias" in results["system_information"]:
            print(f"[+] UTC bias (minutes): {results['system_information']['Bias']}")

     
        print("\n[USB storage devices]")
        control_sets_to_check = [control_set]
        if "ControlSet002" not in control_sets_to_check:
            control_sets_to_check.append("ControlSet002")

        usb_records = {}
        for selected_set in control_sets_to_check:
            try:
                usb_key = reg.open(rf"{selected_set}\Enum\USBSTOR")
                for device_key in usb_key.subkeys():
                    for instance_key in device_key.subkeys():
                        friendly_name = read_value(instance_key, "FriendlyName")
                        manufacturer = read_value(instance_key, "Mfg")
                        record = {
                            "device": device_key.name(),
                            "instance_id": instance_key.name(),
                            "friendly_name": readable_value(friendly_name) if friendly_name is not None else device_key.name(),
                            "manufacturer": readable_value(manufacturer) if manufacturer is not None else None,
                            "control_set": selected_set,
                        }
                        identity = (record["device"], record["instance_id"])
                        usb_records.setdefault(identity, record)
            except Exception:
                continue

        results["usb_history"] = list(usb_records.values())
        for item in results["usb_history"]:
            print(f"[+] {item['friendly_name']}")
            print(f"    Instance: {item['instance_id']}")
        if not results["usb_history"]:
            print("[+] No USBSTOR devices found.")

       
        print("\n[Mounted drive mappings]")
        mounted_key = reg.open("MountedDevices")
        mounted_values = {}
        for value in mounted_key.values():
            name = value.name()
            raw = value.value()
            if isinstance(raw, bytes):
                mounted_values[name] = raw

        volume_by_data = {}
        for name, raw in mounted_values.items():
            match = re.match(r"^\\\?\?\\Volume\{([^}]+)\}$", name, re.IGNORECASE)
            if match:
                volume_by_data[raw] = match.group(1)

        drive_mappings = {}
        for name, raw in mounted_values.items():
            if re.match(r"^\\DosDevices\\[A-Z]:$", name, re.IGNORECASE):
                drive_letter = name.rsplit("\\", 1)[-1]
                volume_guid = volume_by_data.get(raw)
                drive_mappings[drive_letter] = {
                    "volume_guid": volume_guid
                }
                results["mounted_devices"][drive_letter] = {
                    "volume_guid": volume_guid
                }

        for drive_letter in sorted(drive_mappings):
            volume_guid = drive_mappings[drive_letter]["volume_guid"]
            if volume_guid:
                print(f"[+] {drive_letter} -> Volume {{{volume_guid}}}")
            else:
                print(f"[+] {drive_letter} -> Volume identifier not resolved")

        if not drive_mappings:
            print("[+] No drive-letter mappings found.")

    except Exception as error:
        record_error("SYSTEM hive analysis", error)


def analyze_installed_apps():
    print_section("RELEVANT INSTALLED APPLICATIONS")
    try:
        reg = open_hive(HIVE_FILES["SOFTWARE"])
        uninstall_key = reg.open(r"Microsoft\Windows\CurrentVersion\Uninstall")


        excluded_terms = (
            "security update", "update for", "hotfix", "kb", "language pack",
            "service pack", "redistributable", "driver", "device software",
            "windows installer", "microsoft visual c++", ".net framework",
            "internet explorer", "windows internet explorer", "microsoft update"
        )
        included_publishers = (
            "google", "apple", "eraser", "piriform", "ccleaner",
            "microsoft corporation", "microsoft office"
        )

        selected = {}
        for app_key in uninstall_key.subkeys():
            display_name = read_value(app_key, "DisplayName")
            if not display_name:
                continue

            name = readable_value(display_name).strip()
            folded = name.casefold()
            publisher_value = read_value(app_key, "Publisher")
            publisher = readable_value(publisher_value).strip() if publisher_value is not None else "Not recorded"

            if any(term in folded for term in excluded_terms):
                continue

            
            publisher_folded = publisher.casefold()
            relevant = (
                any(term in publisher_folded for term in included_publishers)
                or any(term in folded for term in ("google drive", "icloud", "eraser", "ccleaner", "office"))
            )
            if not relevant:
                continue

            version_value = read_value(app_key, "DisplayVersion")
            app_info = {
                "name": name,
                "version": readable_value(version_value) if version_value is not None else "Not recorded",
                "publisher": publisher,
            }
            selected.setdefault(folded, app_info)

        results["installed_applications"] = sorted(
            selected.values(), key=lambda item: item["name"].casefold()
        )

        for app in results["installed_applications"]:
            print(f"[+] {app['name']} | Version: {app['version']}")

        print(f"[+] Relevant applications identified: {len(results['installed_applications'])}")
        print("[+] Routine Windows components and update entries omitted from the display.")

    except Exception as error:
        record_error("Installed applications analysis", error)


def analyze_appcompat():
    print_section("APPLICATION COMPATIBILITY RECORDS")
    import xml.etree.ElementTree as ET

    xml_path = evidence_path(OPTIONAL_FILES["AEINV_PREVIOUS"])
    if not os.path.isfile(xml_path):
        print("[-] AEINV_PREVIOUS.xml is unavailable.")
        return

    try:
        root = ET.parse(xml_path).getroot()
        for element in root.iter("Program"):
            record = {
                "source": "AEINV_PREVIOUS.xml",
                "name": element.attrib.get("Name"),
                "publisher": element.attrib.get("Publisher"),
                "version": element.attrib.get("Version"),
                "source_type": element.attrib.get("Source"),
                "attributes": dict(element.attrib),
            }
            results["application_compatibility"].append(record)
            if record["name"]:
                print(
                    f"[+] {record['name']} | "
                    f"Version: {record['version'] or 'Not recorded'} | "
                    f"Publisher: {record['publisher'] or 'Not recorded'}"
                )

        print(f"[+] Program records extracted: {len(results['application_compatibility'])}")
    except Exception as error:
        record_error("AEINV_PREVIOUS.xml analysis", error)



def analyze_recent_file_cache():
    print_section("RECENT FILE CACHE")
    cache_path = evidence_path(OPTIONAL_FILES["RecentFileCache"])
    if not os.path.isfile(cache_path):
        print("[-] RecentFileCache.bcf is unavailable.")
        return

    try:
        with open(cache_path, "rb") as file:
            data = file.read()

        strings = [
            item.decode("ascii", errors="ignore")
            for item in re.findall(rb"[\x20-\x7E]{5,}", data)
        ]
        strings.extend(
            item.decode("utf-16le", errors="ignore")
            for item in re.findall(rb"(?:[\x20-\x7E]\x00){5,}", data)
        )

        unique_strings = sorted(set(item.strip() for item in strings if item.strip()))
        for item in unique_strings:
            results["application_compatibility"].append({
                "source": "RecentFileCache.bcf",
                "type": "extracted_string",
                "value": item,
            })
            print(f"[+] {item}")

        print(f"[+] Unique strings extracted: {len(unique_strings)}")
    except Exception as error:
        record_error("RecentFileCache analysis", error)



def export_json_report():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report_path = os.path.join(OUTPUT_DIR, "forensic_analysis_report.json")
    with open(report_path, "w", encoding="utf-8") as report_file:
        json.dump(results, report_file, indent=4, ensure_ascii=False, default=str)
    print(f"\n[+] JSON report saved to: {os.path.abspath(report_path)}")


def main():
    print_section("DIGITAL FORENSICS ANALYZER")
    check_evidence()
    analyzer_software()
    analyze_sam()
    analyze_ntuser()
    analyze_system()
    analyze_installed_apps()
    analyze_appcompat()
    analyze_recent_file_cache()

    print_section("INVESTIGATION SUMMARY")
    print(f"[+] User account entries: {len(results['user_accounts'])}")
    print(f"[+] Installed applications: {len(results['installed_applications'])}")
    print(f"[+] USB device instances: {len(results['usb_history'])}")
    print(f"[+] User activity entries: {len(results['user_activity'])}")
    print(f"[+] RunMRU entries: {len(results['command_history'])}")
    print(f"[+] Application compatibility records: {len(results['application_compatibility'])}")
    print(f"[+] Missing artefacts: {len(results['missing_artifacts'])}")
    print(f"[+] Analysis errors: {len(results['analysis_errors'])}")
    export_json_report()


if __name__ == "__main__":
    main()