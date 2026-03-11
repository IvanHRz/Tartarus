"""TARTARUS Scanner — nmap async wrapper with XML parsing."""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger("tartarus.scanner")

# Scan profiles for IR workflow (30-minute constraint)
PROFILES = {
    "ping": ["-sn"],                                         # 5-15s per /24
    "quick": ["-sS", "--top-ports", "100", "-sV", "-O"],     # 1-3 min per /24
    "standard": ["-sS", "--top-ports", "1000", "-sV", "-O"], # 5-15 min
    "full": ["-sS", "-sV", "-O", "-p-"],                     # 20-45 min
}


def parse_nmap_xml(xml_bytes: bytes) -> list[dict]:
    """Parse nmap XML output into a list of enriched host dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        logger.error("Failed to parse nmap XML output")
        return hosts

    for host_el in root.findall("host"):
        # Skip hosts that are down
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        host = {
            "ip": None,
            "hostname": None,
            "mac_address": None,
            "mac_vendor": None,
            "os_fingerprint": None,
            "os_accuracy": None,
            "open_ports": [],
            "uptime_seconds": None,
            "last_boot": None,
            "distance": None,
            "state_reason": None,
        }

        # State reason (why host is considered "up")
        if status is not None:
            host["state_reason"] = status.get("reason", "")

        # IP + MAC address
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                host["mac_address"] = addr.get("addr")
                host["mac_vendor"] = addr.get("vendor", "")

        if not host["ip"]:
            continue

        # Hostname
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host["hostname"] = hn.get("name")

        # Open ports with service details
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    service = port.find("service")
                    port_info = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "service": service.get("name", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "product": service.get("product", "") if service is not None else "",
                        "extrainfo": service.get("extrainfo", "") if service is not None else "",
                    }
                    # NSE script output for this port
                    scripts = port.findall("script")
                    if scripts:
                        port_info["scripts"] = {
                            s.get("id", ""): s.get("output", "")
                            for s in scripts
                        }
                    host["open_ports"].append(port_info)

        # OS fingerprint (best match)
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                host["os_fingerprint"] = osmatch.get("name", "")
                host["os_accuracy"] = osmatch.get("accuracy", "")

        # Uptime
        uptime = host_el.find("uptime")
        if uptime is not None:
            host["uptime_seconds"] = uptime.get("seconds")
            host["last_boot"] = uptime.get("lastboot")

        # Distance (hops)
        distance = host_el.find("distance")
        if distance is not None:
            host["distance"] = distance.get("value")

        hosts.append(host)

    return hosts


async def run_scan(target: str, profile: str = "quick") -> list[dict]:
    """Run nmap scan asynchronously and return parsed hosts."""
    args = ["nmap", "-oX", "-", "--noninteractive"]
    args += PROFILES.get(profile, PROFILES["quick"])
    args.append(target)

    logger.info("Starting nmap scan: %s (profile: %s)", target, profile)

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        logger.error("nmap failed (exit %d): %s", proc.returncode, stderr.decode())
        return []

    hosts = parse_nmap_xml(stdout)
    logger.info("Scan complete: %d hosts found for %s", len(hosts), target)
    return hosts
