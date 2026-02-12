# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import sys
from pathlib import Path

sys.path.append("./configs")
import argparse
import asyncio
import logging
import re
import time
import os
from ipaddress import ip_address
import uuid
import flask.cli
import requests
import xmltodict
from netmiko import ConnectHandler
from flask import Flask, Response, render_template, request, send_from_directory


PROVISIONING_API_URL = os.getenv("PROVISIONING_API_URL", "http://localhost:8000")
ENABLE_SSH_COMPLIANCE = os.getenv("ENABLE_SSH_COMPLIANCE", "0") == "1"

SSH_USER = os.getenv("SWITCH_SSH_USER", "")
SSH_PASS = os.getenv("SWITCH_SSH_PASS", "")
SSH_SECRET = os.getenv("SWITCH_SSH_SECRET", "")
SSH_DEVICE_TYPE = os.getenv("SWITCH_SSH_DEVICE_TYPE", "cisco_ios")
SSH_TIMEOUT = int(os.getenv("SWITCH_SSH_TIMEOUT", "20"))
SSH_RETRIES = int(os.getenv("SSH_RETRIES", "6"))
SSH_RETRY_SLEEP = int(os.getenv("SSH_RETRY_SLEEP", "10"))

IOS_VERSION_RE = re.compile(r"Version\s+([\w\.\(\)\-]+)")
IOS_MODEL_RE_1 = re.compile(r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)")
IOS_MODEL_RE_2 = re.compile(r"[Cc]isco\s+(\S+)\s+\(")  # ejemplo: "cisco C9300-24T (X86)..."


def get_ips_from_api(serial: str):
    try:
        url = f"{PROVISIONING_API_URL}/switches/ips/{serial}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[IP-LOOKUP] Failed to get IPs for {serial}: {e}")
        return {}


def parse_show_version(output: str):
    version = None
    model = None

    m = IOS_VERSION_RE.search(output)
    if m:
        version = m.group(1)

    m = IOS_MODEL_RE_1.search(output)
    if m:
        model = m.group(1)

    if not model:
        m = IOS_MODEL_RE_2.search(output)
        if m:
            model = m.group(1)

    return model, version

def notify_api_report_ip(serial: str, last_seen_ip: str):
    try:
        url = f"{PROVISIONING_API_URL}/switches/report-ip"
        payload = {
            "serial_number": serial,
            "last_seen_ip": last_seen_ip,
        }
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
    except Exception as e:
        # IMPORTANTÍSIMO: no romper PnP si falla la API
        print(f"[IP-REPORT] Failed for serial={serial} ip={last_seen_ip}: {e}")

def ssh_get_model_version(host: str):
    if not SSH_USER or not SSH_PASS:
        raise RuntimeError("Missing SWITCH_SSH_USER/SWITCH_SSH_PASS env vars")

    device = {
        "device_type": SSH_DEVICE_TYPE,
        "host": host,
        "username": SSH_USER,
        "password": SSH_PASS,
        "secret": SSH_SECRET or None,
        "timeout": SSH_TIMEOUT,
        "conn_timeout": SSH_TIMEOUT,
        "banner_timeout": SSH_TIMEOUT,
        "auth_timeout": SSH_TIMEOUT,
    }

    conn = ConnectHandler(**device)
    try:
        if SSH_SECRET:
            conn.enable()
        out = conn.send_command("show version", read_timeout=SSH_TIMEOUT)
        return parse_show_version(out)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

def report_version_to_api(serial: str, model: str | None, version: str):
    payload = {
        "serial_number": serial,
        "current_version": version,
        "model": model,
    }
    r = requests.post(f"{PROVISIONING_API_URL}/switches/report-version", json=payload, timeout=15)
    r.raise_for_status()
    return r.json()

def poll_ssh_and_report(serial: str, ip: str):
    last_err = None
    for attempt in range(1, SSH_RETRIES + 1):
        try:
            model, ver = ssh_get_model_version(ip)
            if not ver:
                raise RuntimeError("Could not parse current_version from 'show version'")
            result = report_version_to_api(serial, model, ver)
            return result
        except Exception as e:
            last_err = e
            print(f"[SSH] attempt {attempt}/{SSH_RETRIES} failed for {serial}@{ip}: {e}")
            time.sleep(SSH_RETRY_SLEEP)
    raise RuntimeError(f"SSH poll failed after {SSH_RETRIES} attempts: {last_err}")

def notify_api_config_applied(serial):
    try:
        res = requests.post(
            "http://provisioning_api:8000/switches/config-applied",
            data={"serial_number": serial},
            timeout=5
        )
        print("Notification API:", res.text)
    except Exception as e:
        print("Error notificando API:", e)


# disable default Flask logging to stdout
logging.getLogger("werkzeug").disabled = True
flask.cli.show_server_banner = lambda *args: None


# get local IP logic
async def get_local_ip():
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("8.8.8.8", 80)
    )
    localip = transport.get_extra_info("sockname")[0]
    transport.close()
    return localip


# ArgumentParser
parser = argparse.ArgumentParser(prog="OpenPnPServer")
parser.add_argument(
    "-i",
    "--ip",
    type=ip_address,
    help="IP the Server should Listen on, Default local IP",
)
parser.add_argument(
    "-p",
    "--port",
    type=int,
    default="8080",
    help="Port the Server should Listen on, Default 8080",
)
args = parser.parse_args()

if not args.ip:
    LOCAL_IP = asyncio.run(get_local_ip())
else:
    LOCAL_IP = str(args.ip)

LOCAL_PORT = str(args.port)

# build var from args or local values/defaults
HTTP_SERVER = LOCAL_IP + ":" + LOCAL_PORT


# we are ready
print(f"\nServer will run on IP:{LOCAL_IP} and Port:{LOCAL_PORT}\n")


# Flask
app = Flask(__name__, template_folder="./templates")
current_dir = Path(__file__)

SERIAL_NUM_RE = re.compile(
    r"PID:(?P<product_id>\w+(?:-\w+)*),VID:(?P<hw_version>\w+),SN:(?P<serial_number>\w+)"
)

# Regex alternativo para Catalyst 2960 / 2960X que usan "+" en el PID
SERIAL_NUM_RE_2960 = re.compile(
    r"PID:(?P<product_id>[A-Za-z0-9+\-]+),VID:(?P<hw_version>\w+),SN:(?P<serial_number>\w+)"
    
)

def work_request(host, call="device_info"):
    url = f"http://{host}/pnp/WORK-REQUEST"
    with open(current_dir / f"{call}.xml", encoding="ascii") as f:
        data = f.read()
    return requests.post(url, data, timeout=3)


def get_device_info(host):
    url = f"http://{host}/pnp/WORK-REQUEST"


@app.route("/test-xml")
def test_xml():
    jinja_context = {
        "http_server": HTTP_SERVER,
        "config_filename": "test.cfg",
        "udi": 123,
        "correlator_id": 123,
    }
    result = render_template("load_config.xml", **jinja_context)
    return Response(result, mimetype="text/xml")


@app.route("/")
def root():
    src_add = request.environ.get("HTTP_X_REAL_IP", request.remote_addr)
    print(f"SOURCE-ADDRESS: {src_add}")
    return "Hello!"


@app.route("/configs/<path:path>")
def serve_configs(path):
    return send_from_directory("configs", path)


@app.route("/images/<path:path>")
def serve_sw_images(path):
    return send_from_directory("sw_images", path)


@app.route("/pnp/HELLO")
def pnp_hello():
    return "", 200


@app.route("/pnp/WORK-REQUEST", methods=["POST"])
def pnp_work_request():
    print(request.data.decode())

    data = xmltodict.parse(request.data)
    pnp = data.get("pnp", {}) or {}

    info = pnp.get("info", {}) or {}
    if isinstance(info, list):
        info = info[0] if info else {}

    correlator_id = (
        info.get("@correlator")
        or info.get("correlator")
        or str(uuid.uuid4())
    )

    udi = (
        pnp.get("@udi")
        or pnp.get("udi")
        or info.get("@udi")
        or info.get("udi")
    )

    if isinstance(udi, dict):
        udi = udi.get("#text") or udi.get("text") or udi.get("_")

    if not udi:
        return Response("Missing UDI in PnP WORK-REQUEST", status=400, mimetype="text/plain")

    udi_match = SERIAL_NUM_RE.search(udi)
    if not udi_match:
        udi_match = SERIAL_NUM_RE_2960.search(udi)

    if not udi_match:
        return Response(f"UDI format not recognized: {udi}", status=400, mimetype="text/plain")

    serial_number = udi_match.group("serial_number")
    ip = request.remote_addr
    notify_api_report_ip(serial, ip)

    try:
        config_file = serial_number
        jinja_context = {
            "udi": udi,
            "correlator_id": correlator_id,
            "config_filename": config_file,
            "http_server": HTTP_SERVER,
        }
        result_data = render_template("load_config.xml", **jinja_context)
        sys.stderr.write("Loading " + config_file + " on " + request.environ["REMOTE_ADDR"] + "\n")
        return Response(result_data, mimetype="text/xml")
    except Exception:
        sys.stderr.write(
            "Unable to load "
            + config_file
            + ".cfg"
            + " on "
            + request.environ["REMOTE_ADDR"]
            + " ("
            + serial_number
            + ")\n"
        )
        return ""

@app.route("/pnp/WORK-RESPONSE", methods=["POST"])
def pnp_work_response():
    print(request.data)
    data = xmltodict.parse(request.data)

    pnp = data.get("pnp", {}) if isinstance(data, dict) else {}

    # --- Correlator: opcional ---
    correlator_id = (
        pnp.get("response", {}).get("@correlator")
        if isinstance(pnp.get("response", {}), dict)
        else None
    )
    if not correlator_id:
        correlator_id = "missing-correlator"

    # --- UDI: tolerante ---
    def _normalize_text(value):
        if value is None:
            return None
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, dict):
            value = value.get("#text") or value.get("@udi")
        if isinstance(value, str):
            value = value.strip()
        return value

    udi = _normalize_text(pnp.get("@udi"))

    if not udi:
        info = pnp.get("info")
        if isinstance(info, dict):
            udi = _normalize_text(info.get("udi"))

    if not udi:
        resp = pnp.get("response")
        if isinstance(resp, dict):
            info2 = resp.get("info")
            if isinstance(info2, dict):
                udi = _normalize_text(info2.get("udi"))

    if not udi:
        return Response("Missing UDI in WORK-RESPONSE", status=400, mimetype="text/plain")

    # --- Extraer serial ---
    match = SERIAL_NUM_RE.match(udi) or SERIAL_NUM_RE_2960.match(udi)
    serial = match.group("serial_number") if match else None

    if serial:
        # 1) Notificar config aplicada (no debe tumbar el PnP si falla)
        try:
            notify_api_config_applied(serial)
        except Exception as e:
            print("Failed to notify provisioning API (config-applied):", e)

        # 2) SSH/compliance con fallback de IPs
        if ENABLE_SSH_COMPLIANCE:
            # obtener mgmt_ip / last_seen_ip desde la API
            ips = get_ips_from_api(serial) or {}

            candidates = []
            mgmt_ip = ips.get("mgmt_ip")
            last_seen_ip = ips.get("last_seen_ip")

            if mgmt_ip:
                candidates.append(mgmt_ip)

            if last_seen_ip and last_seen_ip not in candidates:
                candidates.append(last_seen_ip)

            # fallback final (útil para lab / simulación)
            req_ip = request.headers.get("X-SWITCH-IP") or request.remote_addr
            if req_ip and req_ip not in candidates:
                candidates.append(req_ip)

            ssh_ok = False
            last_err = None

            for ip in candidates:
                try:
                    print(f"[SSH] Trying {serial} on {ip}")
                    result = poll_ssh_and_report(serial, ip)
                    ssh_ok = True
                    print(
                        f"[COMPLIANCE] serial={serial} ip={ip} "
                        f"state={result.get('state')} "
                        f"current={result.get('current_version')} "
                        f"recommended={result.get('recommended_version')}"
                    )
                    break
                except Exception as e:
                    last_err = e
                    print(f"[SSH] Failed {serial} on {ip}: {e}")

            if not ssh_ok:
                print(f"[SSH] All IPs failed for {serial}: {last_err}")
    else:
        print(f"Could not parse serial from UDI: {udi}")

    # --- Responder al switch (bye) ---
    jinja_context = {"udi": udi, "correlator_id": correlator_id}
    result_data = render_template("bye.xml", **jinja_context)
    return Response(result_data, mimetype="text/xml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=LOCAL_PORT)
