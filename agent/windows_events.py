
import json
import socket
import time
import traceback

from pathlib import Path
from xml.etree import ElementTree

import requests
import win32evtlog

from transport import post_event

API_URL = "http://127.0.0.1:8001/events"

POLL_INTERVAL = 10
MAX_EVENTS_PER_PASS = 100
BATCH_SIZE = 20

STATE_FILE = Path(__file__).with_name(
    "windows_events_cursor.json"
)

XML_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def load_cursor():
    if not STATE_FILE.exists():
        return 0

    try:
        data = json.loads(
            STATE_FILE.read_text(encoding="utf-8")
        )

        record_id = int(data["last_record_id"])

        if record_id < 0:
            raise ValueError("Negative record ID")

        return record_id

    except (OSError, ValueError, KeyError, TypeError) as error:
        raise RuntimeError(
            "Cursor file is invalid. Inspect it before restarting."
        ) from error


def save_cursor(record_id):
    temporary_file = STATE_FILE.with_suffix(".tmp")

    temporary_file.write_text(
        json.dumps({"last_record_id": record_id}),
        encoding="utf-8",
    )

    temporary_file.replace(STATE_FILE)


def parse_event(event_handle):
    xml_text = win32evtlog.EvtRender(
        event_handle,
        win32evtlog.EvtRenderEventXml,
    )

    root = ElementTree.fromstring(xml_text)

    record_id = int(
        root.findtext(
            "./e:System/e:EventRecordID",
            namespaces=XML_NS,
        )
    )

    time_element = root.find(
        "./e:System/e:TimeCreated",
        XML_NS,
    )

    timestamp = time_element.attrib["SystemTime"]

    values = {}

    for field in root.findall(
        "./e:EventData/e:Data",
        XML_NS,
    ):
        name = field.attrib.get("Name")

        if name:
            values[name] = field.text or ""

    return {
        "record_id": record_id,
        "timestamp": timestamp,
        "username": values.get("TargetUserName", "unknown"),
        "source_ip": values.get("IpAddress", "-"),
        "logon_type": values.get("LogonType", "unknown"),
        "status": values.get("Status", "unknown"),
    }



def read_failed_logons(last_record_id):
    query = (
        "*[System[(EventID=4625) and "
        f"(EventRecordID > {int(last_record_id)})]]"
    )

    flags = (
        win32evtlog.EvtQueryChannelPath
        | win32evtlog.EvtQueryForwardDirection
    )

    records = []

    query_handle = win32evtlog.EvtQuery(
        "Security",
        flags,
        query,
    )

    try:
        while len(records) < MAX_EVENTS_PER_PASS:

            batch_size = min(
                BATCH_SIZE,
                MAX_EVENTS_PER_PASS - len(records),
            )

            batch = win32evtlog.EvtNext(
                query_handle,
                batch_size,
                0,
            )

            if not batch:
                break

            try:
                for event_handle in batch:
                    records.append(
                        parse_event(event_handle)
                    )

            finally:
                for event_handle in batch:
                    event_handle.Close()

    finally:
        query_handle.Close()

    return records


def send_event(record):
    event = {
        "hostname": socket.gethostname(),
        "event_type": "windows_failed_logon",
        "description": (
            f"Windows Event 4625: failed sign-in for "
            f"{record['username']}; "
            f"source={record['source_ip']}; "
            f"logon_type={record['logon_type']}; "
            f"status={record['status']}"
        ),
        "severity": "low",
        "timestamp": record["timestamp"],
    }

    post_event(event)


def main():
    print("[START] LinkShield Windows Security Collector")

    last_record_id = load_cursor()

    print(f"[CURSOR] Resuming after record {last_record_id}")

    while True:
        try:
            records = read_failed_logons(last_record_id)

            for record in records:
                send_event(record)

                last_record_id = record["record_id"]
                save_cursor(last_record_id)

                print(
                    f"[SENT] Event 4625 "
                    f"| Record: {last_record_id} "
                    f"| User: {record['username']} "
                    f"| Source: {record['source_ip']}"
                )

            if records:
                print(f"[INFO] Forwarded {len(records)} records")

        except Exception:
            print("[ERROR] Windows event collection failed")
            traceback.print_exc()

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[STOP] Windows collector stopped")
