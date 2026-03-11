"""TARTARUS Scanner — nmap async wrapper with XML parsing."""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger("tartarus.scanner")

# Scan profiles for IR workflow (30-minute constraint)
PROFILES = {
    "ping": ["-sn"],                                    # 5-15s per /24
    "quick": ["-sS", "--top-ports", "100", "-sV"],      # 1-3 min per /24
    "standard": ["-sS", "--top-ports", "1000", "-sV", "-O"],  # 5-15 min
    "full": ["-sS", "-sV", "-O", "-p-"],                # 20-45 min
}


def parse_nmap_xml(xml_bytes: bytes) -> list[dict]:
    """Parse nmap XML output into a list of host dicts."""
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
            "os_fingerprint": None,
            "open_ports": [],
        }

        # IP address
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                host["mac_address"] = addr.get("addr")

        if not host["ip"]:
            continue

        # Hostname
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host["hostname"] = hn.get("name")

        # Open ports
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
                    }
                    host["open_ports"].append(port_info)

        # OS fingerprint
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                host["os_fingerprint"] = osmatch.get("name", "")

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
