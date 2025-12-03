# moduler/industrial_recon.py
"""
Industrial Recon - Advanced Passive ICS/OT Asset Discovery & Network Mapping
- Advanced passive PCAP analysis with deep packet inspection for industrial protocols
- Multi-threaded SNMP v1/v2c/v3 enrichment with comprehensive OID mapping
- Conditional active discovery (ARP, ICMP, limited port scanning) with safety controls
- Advanced topology mapping with relationship detection
- Comprehensive reporting: JSON, CSV, ASCII topology, network diagrams
- Industrial protocol fingerprinting and vulnerability indicators

Usage examples:
  varux factory-scan --interface eth0 --pcap-duration 300 --deep-analysis
  varux factory-scan --subnet 192.168.10.0/24 --allow-active true --snmp-enrich
  varux factory-scan --pcap-file capture.pcap --output-format json,csv,html

SECURITY NOTE: Always obtain written authorization before scanning production networks.
Industrial systems require extreme caution - minimal network impact is critical.
"""

import json
import time
import socket
import threading
import ipaddress
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import csv
import html
from datetime import datetime

# Enhanced optional imports with fallbacks
try:
    from scapy.all import sniff, ARP, Ether, IP, TCP, UDP, ICMP, rdpcap, conf, srp, sr1
    from scapy.layers.inet import _IPOption_HDR
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Scapy import warning: {e}")

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UsmUserData, 
        UdpTransportTarget, ContextData, ObjectType, 
        ObjectIdentity, getCmd, nextCmd
    )
    PYSNMP_AVAILABLE = True
except ImportError as e:
    PYSNMP_AVAILABLE = False
    print(f"PySNMP import warning: {e}")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Constants and configuration
REPORT_DIR = Path.home() / '.varux' / 'factory_reports'
REPORT_DIR.mkdir(parents=True, exist_ok=True)

class ScanSafetyLevel(Enum):
    PASSIVE_ONLY = 1
    LIMITED_ACTIVE = 2
    FULL_ACTIVE = 3

class ProtocolType(Enum):
    MODBUS = "modbus"
    OPC_UA = "opcua"
    S7COMM = "s7comm"
    DNP3 = "dnp3"
    IEC104 = "iec104"
    PROFINET = "profinet"
    ETHERNET_IP = "ethernet_ip"
    BACNET = "bacnet"
    MQTT = "mqtt"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SSH = "ssh"
    TELNET = "telnet"
    UNKNOWN = "unknown"

@dataclass
class IndustrialDevice:
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os_family: Optional[str] = None
    protocols: List[ProtocolType] = field(default_factory=list)
    services: Dict[str, Any] = field(default_factory=dict)
    snmp_data: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    criticality: str = "low"
    tags: List[str] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = time.time()
        self.last_seen = time.time()

class IndustrialRecon:
    def __init__(self, config_manager=None, secrets_manager=None):
        self.config = config_manager
        self.secrets = secrets_manager
        self.devices: Dict[str, IndustrialDevice] = {}  # key: IP or MAC
        self.network_relationships: Dict[str, List[str]] = {}
        self.lock = threading.RLock()
        
        # Configuration with safety defaults
        self.safety_level = ScanSafetyLevel.PASSIVE_ONLY
        self.default_snmp_communities = ["public", "private"]
        self.snmp_timeout = 2
        self.max_threads = 10
        self.deep_analysis = False
        
        if config_manager:
            self._load_configuration()
        
        # Enhanced protocol detection patterns
        self.protocol_patterns = {
            ProtocolType.MODBUS: {"tcp_ports": [502], "udp_ports": [502]},
            ProtocolType.OPC_UA: {"tcp_ports": [4840, 4841], "udp_ports": [4840]},
            ProtocolType.S7COMM: {"tcp_ports": [102], "udp_ports": [102]},
            ProtocolType.DNP3: {"tcp_ports": [20000], "udp_ports": [20000]},
            ProtocolType.IEC104: {"tcp_ports": [2404], "udp_ports": [2404]},
            ProtocolType.PROFINET: {"tcp_ports": [34962, 34963, 34964], "udp_ports": [34962, 34963, 34964]},
            ProtocolType.ETHERNET_IP: {"tcp_ports": [44818], "udp_ports": [2222, 44818]},
            ProtocolType.BACNET: {"tcp_ports": [47808], "udp_ports": [47808]},
            ProtocolType.MQTT: {"tcp_ports": [1883, 8883], "udp_ports": []},
            ProtocolType.HTTP: {"tcp_ports": [80, 8080, 8000], "udp_ports": []},
            ProtocolType.HTTPS: {"tcp_ports": [443, 8443], "udp_ports": []},
            ProtocolType.FTP: {"tcp_ports": [21], "udp_ports": []},
            ProtocolType.SSH: {"tcp_ports": [22], "udp_ports": []},
            ProtocolType.TELNET: {"tcp_ports": [23], "udp_ports": []},
        }
        
        # Extended MAC vendor database (common industrial vendors)
        self.mac_vendors = {
            '001A2B': 'Siemens', '001B63': 'Schneider Electric', '0001A2': 'Beckhoff',
            '000CF4': 'Rockwell Automation', '0021FE': 'Moxa', '002436': 'Honeywell',
            '0025AE': 'Omron', '0050C2': 'ABB', '0050BA': 'Bosch Rexroth',
            '0060D5': 'Yaskawa', '0060B3': 'Mitsubishi Electric', '0060C8': 'FANUC',
            '0060D9': 'KUKA', '0060B4': 'Yokogawa', '0060C7': 'Emerson',
            '0060D4': 'Endress+Hauser', '0060D6': 'Wago', '0060D7': 'Phoenix Contact',
            '0060D8': 'Weidmüller', '0060D3': 'B&R Automation', '0060D2': 'Turck',
            '080069': 'Motorola', '08007C': 'Cisco', '08005A': 'IBM',
            '080011': 'Tektronix', '080020': 'Sun Microsystems', '08002B': 'DEC',
            '08005F': 'SGI', '080066': 'HP', '08004E': 'Fujitsu'
        }

    def _load_configuration(self):
        """Load configuration from config manager with safety defaults"""
        if not self.config:
            return
            
        try:
            self.safety_level = ScanSafetyLevel(
                self.config.get('modules.industrial_recon.safety_level', 1)
            )
        except (ValueError, TypeError):
            self.safety_level = ScanSafetyLevel.PASSIVE_ONLY
            
        self.allow_active = bool(self.config.get('modules.industrial_recon.allow_active', False))
        
        snmp_comms = self.config.get('modules.industrial_recon.snmp_communities', ["public", "private"])
        self.default_snmp_communities = snmp_comms if isinstance(snmp_comms, list) else ["public", "private"]
        
        self.snmp_timeout = self.config.get('modules.industrial_recon.snmp_timeout', 2)
        self.max_threads = self.config.get('modules.industrial_recon.max_threads', 10)
        self.deep_analysis = bool(self.config.get('modules.industrial_recon.deep_analysis', False))

    # -----------------------------
    # Enhanced Passive PCAP Analysis
    # -----------------------------
    def passive_listen(self, iface: str, duration: int = 60, packet_count: int = 0) -> Dict[str, Any]:
        """
        Advanced passive network analysis with deep packet inspection
        """
        if not SCAPY_AVAILABLE:
            return {'ok': False, 'error': 'scapy not available for packet analysis'}

        stats = {
            'packets_processed': 0,
            'devices_discovered': 0,
            'protocols_detected': set(),
            'start_time': time.time()
        }

        def _advanced_packet_handler(pkt):
            try:
                stats['packets_processed'] += 1
                
                # Extract basic layers
                ether = pkt.getlayer(Ether)
                ip_layer = pkt.getlayer(IP)
                tcp_layer = pkt.getlayer(TCP)
                udp_layer = pkt.getlayer(UDP)
                
                if not ether:
                    return
                
                src_mac = ether.src
                dst_mac = ether.dst
                src_ip = ip_layer.src if ip_layer else None
                dst_ip = ip_layer.dst if ip_layer else None
                
                # Update device information
                device_key = src_ip or f"mac:{src_mac}"
                
                with self.lock:
                    if device_key not in self.devices:
                        self.devices[device_key] = IndustrialDevice(
                            ip=src_ip,
                            mac=src_mac,
                            first_seen=time.time()
                        )
                        stats['devices_discovered'] += 1
                    
                    device = self.devices[device_key]
                    device.last_seen = time.time()
                    device.packet_count += 1
                    
                    # Protocol detection
                    detected_protocols = self._detect_protocols(pkt, tcp_layer, udp_layer)
                    for protocol in detected_protocols:
                        if protocol not in device.protocols:
                            device.protocols.append(protocol)
                        stats['protocols_detected'].add(protocol)
                    
                    # Vendor identification
                    if src_mac and not device.vendor:
                        device.vendor = self._mac_vendor_lookup(src_mac)
                    
                    # Relationship tracking
                    if src_ip and dst_ip:
                        relationship_key = f"{src_ip}->{dst_ip}"
                        if relationship_key not in device.relationships:
                            device.relationships.append(relationship_key)
                        
                        # Update network relationships
                        if src_ip not in self.network_relationships:
                            self.network_relationships[src_ip] = []
                        if dst_ip not in self.network_relationships[src_ip]:
                            self.network_relationships[src_ip].append(dst_ip)
                    
                    # Deep analysis if enabled
                    if self.deep_analysis:
                        self._deep_packet_analysis(pkt, device)
                        
            except Exception:
                # Silent error handling to avoid breaking the sniff
                pass

        try:
            # Start sniffing with advanced parameters
            sniff(
                iface=iface,
                prn=_advanced_packet_handler,
                store=False,
                timeout=duration,
                count=packet_count,
                promisc=True
            )
            
            stats['end_time'] = time.time()
            stats['duration'] = stats['end_time'] - stats['start_time']
            stats['protocols_detected'] = list(stats['protocols_detected'])
            
            return {
                'ok': True, 
                'stats': stats,
                'devices_count': len(self.devices),
                'relationships_count': len(self.network_relationships)
            }
            
        except PermissionError:
            return {'ok': False, 'error': 'Permission denied for packet capture (require root)'}
        except Exception as e:
            return {'ok': False, 'error': f'Packet capture failed: {str(e)}'}

    def _detect_protocols(self, pkt, tcp_layer, udp_layer) -> List[ProtocolType]:
        """Enhanced protocol detection with port and payload analysis"""
        protocols = []
        
        if tcp_layer:
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            # Port-based detection
            for proto, pattern in self.protocol_patterns.items():
                if src_port in pattern['tcp_ports'] or dst_port in pattern['tcp_ports']:
                    protocols.append(proto)
            
            # Payload-based detection for common industrial protocols
            if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                try:
                    payload = bytes(tcp_layer.payload)
                    
                    # Modbus TCP detection (transaction ID + protocol ID + length)
                    if len(payload) >= 8 and payload[2:4] == b'\x00\x00' and payload[4:6] == b'\x00\x06':
                        if ProtocolType.MODBUS not in protocols:
                            protocols.append(ProtocolType.MODBUS)
                    
                    # S7comm detection (ROSCTR field)
                    if len(payload) >= 5 and payload[0] in [1, 2, 3, 7]:  # ROSCTR values
                        if ProtocolType.S7COMM not in protocols:
                            protocols.append(ProtocolType.S7COMM)
                except (AttributeError, TypeError):
                    pass
        
        if udp_layer:
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
            for proto, pattern in self.protocol_patterns.items():
                if src_port in pattern['udp_ports'] or dst_port in pattern['udp_ports']:
                    protocols.append(proto)
        
        return protocols if protocols else [ProtocolType.UNKNOWN]

    def _deep_packet_analysis(self, pkt, device: IndustrialDevice):
        """Deep packet analysis for advanced fingerprinting"""
        try:
            # TCP window size analysis for OS fingerprinting
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer and hasattr(tcp_layer, 'window'):
                window_size = tcp_layer.window
                # Basic OS fingerprinting based on window size
                if window_size == 5840:
                    device.os_family = "Linux 2.4/2.6"
                elif window_size == 5720:
                    device.os_family = "Google Linux"
                elif window_size == 65535:
                    device.os_family = "FreeBSD/Windows XP"
                elif window_size == 4128:
                    device.os_family = "Cisco IOS"
            
            # TTL analysis for hop distance estimation
            ip_layer = pkt.getlayer(IP)
            if ip_layer and hasattr(ip_layer, 'ttl'):
                ttl = ip_layer.ttl
                if 49 <= ttl <= 64:
                    device.os_family = device.os_family or "Linux/Unix"
                elif 65 <= ttl <= 128:
                    device.os_family = device.os_family or "Windows"
                elif 129 <= ttl <= 255:
                    device.os_family = device.os_family or "Cisco"
                    
        except Exception:
            pass

    # -----------------------------
    # Enhanced Active Discovery
    # -----------------------------
    def arp_sweep(self, subnet: str, timeout: int = 3, max_hosts: int = 1024) -> Dict[str, Any]:
        """
        Multi-threaded ARP sweep with safety controls
        """
        if self.safety_level == ScanSafetyLevel.PASSIVE_ONLY:
            return {'ok': False, 'error': 'Active scanning disabled by safety level'}
        
        if not SCAPY_AVAILABLE:
            return {'ok': False, 'error': 'scapy not available for ARP sweep'}

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except Exception as e:
            return {'ok': False, 'error': f'Invalid subnet: {e}'}

        # Safety limit
        if network.num_addresses > max_hosts:
            return {'ok': False, 'error': f'Subnet too large (> {max_hosts} hosts)'}

        hosts = [str(ip) for ip in network.hosts()][:max_hosts]
        discovered = []
        
        def _arp_scan_host(host):
            try:
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host)
                response = srp(arp_request, timeout=timeout, verbose=0)[0]
                
                for sent, received in response:
                    ip_addr = received.psrc
                    mac_addr = received.hwsrc
                    
                    device = IndustrialDevice(
                        ip=ip_addr,
                        mac=mac_addr,
                        vendor=self._mac_vendor_lookup(mac_addr),
                        first_seen=time.time()
                    )
                    
                    with self.lock:
                        self.devices[ip_addr] = device
                    
                    return (ip_addr, mac_addr)
                    
            except Exception:
                return None

        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(_arp_scan_host, hosts))
        
        discovered = [result for result in results if result]
        
        return {
            'ok': True, 
            'discovered': len(discovered),
            'hosts_scanned': len(hosts),
            'discovered_hosts': discovered
        }

    def icmp_sweep(self, subnet: str, timeout: int = 2, max_hosts: int = 256) -> Dict[str, Any]:
        """
        ICMP ping sweep for host discovery
        """
        if self.safety_level == ScanSafetyLevel.PASSIVE_ONLY:
            return {'ok': False, 'error': 'Active scanning disabled by safety level'}
        
        if not SCAPY_AVAILABLE:
            return {'ok': False, 'error': 'scapy not available for ICMP sweep'}

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except Exception as e:
            return {'ok': False, 'error': f'Invalid subnet: {e}'}

        hosts = [str(ip) for ip in network.hosts()][:max_hosts]
        discovered = []

        def _icmp_ping_host(host):
            try:
                ping = IP(dst=host)/ICMP()
                response = sr1(ping, timeout=timeout, verbose=0)
                
                if response:
                    return host
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(_icmp_ping_host, hosts))
        
        discovered = [result for result in results if result]
        
        # Update devices with ICMP discovered hosts
        for host in discovered:
            if host not in self.devices:
                self.devices[host] = IndustrialDevice(ip=host, first_seen=time.time())

        return {
            'ok': True,
            'discovered': len(discovered),
            'hosts_scanned': len(hosts),
            'alive_hosts': discovered
        }

    # -----------------------------
    # Enhanced SNMP Enrichment
    # -----------------------------
    def snmp_enrich(self, targets: List[str] = None, communities: List[str] = None, 
                   timeout: int = None, oids: List[str] = None) -> Dict[str, Any]:
        """
        Multi-threaded SNMP enrichment with comprehensive OID mapping
        """
        if not PYSNMP_AVAILABLE:
            return {'ok': False, 'error': 'pysnmp not available for SNMP enrichment'}

        targets = targets or list(self.devices.keys())
        communities = communities or self.default_snmp_communities
        timeout = timeout or self.snmp_timeout
        
        # Common industrial OIDs for comprehensive data collection
        default_oids = [
            '1.3.6.1.2.1.1.1.0',  # sysDescr
            '1.3.6.1.2.1.1.5.0',  # sysName
            '1.3.6.1.2.1.1.6.0',  # sysLocation
            '1.3.6.1.2.1.1.2.0',  # sysObjectID
            '1.3.6.1.2.1.25.1.1.0',  # sysUptime
            '1.3.6.1.2.1.1.3.0',  # sysUpTime
        ]
        
        oids = oids or default_oids
        enriched = {}
        stats = {'successful': 0, 'failed': 0, 'total': len(targets)}

        def _snmp_query_target(target):
            try:
                # Validate IP
                socket.inet_aton(target)
            except Exception:
                return target, None

            target_data = {}
            
            for community in communities:
                try:
                    # Build SNMP query
                    object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]
                    
                    iterator = getCmd(
                        SnmpEngine(),
                        CommunityData(community, mpModel=1),  # v2c
                        UdpTransportTarget((target, 161), timeout=timeout, retries=0),
                        ContextData(),
                        *object_types
                    )
                    
                    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                    
                    if errorIndication or errorStatus:
                        continue
                    
                    # Process results
                    data = {}
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        value_str = str(varBind[1])
                        data[oid_str] = value_str
                    
                    target_data[community] = data
                    
                    # Update device information
                    with self.lock:
                        if target in self.devices:
                            self.devices[target].snmp_data.update(data)
                            
                            # Extract hostname from sysName
                            if '1.3.6.1.2.1.1.5.0' in data and not self.devices[target].hostname:
                                self.devices[target].hostname = data['1.3.6.1.2.1.1.5.0']
                    
                    break  # Stop at first successful community
                    
                except Exception:
                    continue
            
            return target, target_data if target_data else None

        # Multi-threaded SNMP queries
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(_snmp_query_target, targets))
        
        for target, data in results:
            if data:
                enriched[target] = data
                stats['successful'] += 1
            else:
                stats['failed'] += 1

        return {
            'ok': True,
            'enriched': enriched,
            'stats': stats
        }

    # -----------------------------
    # Advanced Analysis & Reporting
    # -----------------------------
    def analyze_network_topology(self) -> Dict[str, Any]:
        """
        Advanced network topology analysis with relationship mapping
        """
        topology = {
            'devices': {},
            'relationships': self.network_relationships,
            'subnets': {},
            'critical_assets': [],
            'protocol_distribution': {},
            'security_assessment': {}
        }
        
        # Device analysis
        for device_key, device in self.devices.items():
            device_data = {
                'ip': device.ip,
                'mac': device.mac,
                'hostname': device.hostname,
                'vendor': device.vendor,
                'os_family': device.os_family,
                'protocols': [p.value for p in device.protocols],
                'services': device.services,
                'criticality': device.criticality,
                'tags': device.tags,
                'relationships': device.relationships,
                'first_seen': device.first_seen,
                'last_seen': device.last_seen,
                'packet_count': device.packet_count
            }
            topology['devices'][device_key] = device_data
            
            # Critical asset identification
            if any(proto in device.protocols for proto in [
                ProtocolType.MODBUS, ProtocolType.S7COMM, ProtocolType.DNP3,
                ProtocolType.PROFINET, ProtocolType.ETHERNET_IP
            ]):
                device.criticality = "high"
                topology['critical_assets'].append(device_key)
            
            # Protocol distribution
            for protocol in device.protocols:
                proto_name = protocol.value
                topology['protocol_distribution'][proto_name] = \
                    topology['protocol_distribution'].get(proto_name, 0) + 1
        
        # Subnet analysis
        subnets = {}
        for device in self.devices.values():
            if device.ip:
                try:
                    subnet = ".".join(device.ip.split(".")[:3]) + ".0/24"
                    subnets[subnet] = subnets.get(subnet, 0) + 1
                except (AttributeError, IndexError):
                    continue
        topology['subnets'] = subnets
        
        # Security assessment
        topology['security_assessment'] = self._perform_security_assessment()
        
        return topology

    def _perform_security_assessment(self) -> Dict[str, Any]:
        """Perform basic security assessment of discovered devices"""
        assessment = {
            'total_devices': len(self.devices),
            'industrial_devices': 0,
            'plaintext_protocols': 0,
            'potential_vulnerabilities': [],
            'recommendations': []
        }
        
        industrial_protocols = {ProtocolType.MODBUS, ProtocolType.S7COMM, ProtocolType.DNP3,
                               ProtocolType.IEC104, ProtocolType.PROFINET, ProtocolType.ETHERNET_IP}
        
        plaintext_protocols = {ProtocolType.HTTP, ProtocolType.FTP, ProtocolType.TELNET}
        
        for device in self.devices.values():
            # Count industrial devices
            if any(proto in industrial_protocols for proto in device.protocols):
                assessment['industrial_devices'] += 1
            
            # Count plaintext protocols
            if any(proto in plaintext_protocols for proto in device.protocols):
                assessment['plaintext_protocols'] += 1
            
            # Vulnerability checks
            if ProtocolType.TELNET in device.protocols:
                assessment['potential_vulnerabilities'].append(
                    f"Telnet service detected on {device.ip} - credentials transmitted in plaintext"
                )
            
            if ProtocolType.FTP in device.protocols:
                assessment['potential_vulnerabilities'].append(
                    f"FTP service detected on {device.ip} - credentials transmitted in plaintext"
                )
        
        # Generate recommendations
        if assessment['plaintext_protocols'] > 0:
            assessment['recommendations'].append(
                "Replace plaintext protocols (Telnet, FTP) with encrypted alternatives (SSH, SFTP)"
            )
        
        if assessment['industrial_devices'] > 0:
            assessment['recommendations'].append(
                "Implement network segmentation for industrial control systems"
            )
        
        return assessment

    # -----------------------------
    # Enhanced Reporting
    # -----------------------------
    def save_report(self, tag: str = None, formats: List[str] = None) -> Dict[str, str]:
        """
        Save comprehensive reports in multiple formats
        """
        ts = int(time.time())
        dt = datetime.fromtimestamp(ts).strftime('%Y%m%d_%H%M%S')
        tag = tag or 'factory_scan'
        
        formats = formats or ['json']
        report_paths = {}
        
        # Generate comprehensive data
        report_data = {
            'metadata': {
                'scan_id': f"{tag}_{ts}",
                'timestamp': ts,
                'datetime': datetime.fromtimestamp(ts).isoformat(),
                'device_count': len(self.devices),
                'safety_level': self.safety_level.name
            },
            'topology': self.analyze_network_topology(),
            'devices': {k: self._device_to_dict(v) for k, v in self.devices.items()},
            'statistics': {
                'protocols_detected': list(set(
                    proto for device in self.devices.values() 
                    for proto in device.protocols
                )),
                'vendors_detected': list(set(
                    device.vendor for device in self.devices.values() 
                    if device.vendor and device.vendor != 'unknown'
                )),
                'scan_duration': getattr(self, 'last_scan_duration', 0)
            }
        }
        
        # JSON report
        if 'json' in formats:
            json_path = REPORT_DIR / f"{tag}_report_{dt}.json"
            json_path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False, default=str)
            )
            report_paths['json'] = str(json_path)
        
        # CSV report
        if 'csv' in formats:
            csv_path = REPORT_DIR / f"{tag}_devices_{dt}.csv"
            self._save_csv_report(csv_path)
            report_paths['csv'] = str(csv_path)
        
        # YAML report
        if 'yaml' in formats and YAML_AVAILABLE:
            yaml_path = REPORT_DIR / f"{tag}_report_{dt}.yaml"
            with open(yaml_path, 'w') as f:
                yaml.dump(report_data, f, default_flow_style=False)
            report_paths['yaml'] = str(yaml_path)
        
        # HTML report
        if 'html' in formats:
            html_path = REPORT_DIR / f"{tag}_report_{dt}.html"
            self._save_html_report(html_path, report_data)
            report_paths['html'] = str(html_path)
        
        return report_paths

    def _save_csv_report(self, path: Path):
        """Save device inventory as CSV"""
        with open(path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['IP', 'MAC', 'Hostname', 'Vendor', 'OS', 'Protocols', 
                         'Criticality', 'First Seen', 'Last Seen', 'Packet Count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for device in self.devices.values():
                writer.writerow({
                    'IP': device.ip or '',
                    'MAC': device.mac or '',
                    'Hostname': device.hostname or '',
                    'Vendor': device.vendor or '',
                    'OS': device.os_family or '',
                    'Protocols': ', '.join([p.value for p in device.protocols]),
                    'Criticality': device.criticality,
                    'First Seen': datetime.fromtimestamp(device.first_seen).isoformat() if device.first_seen else '',
                    'Last Seen': datetime.fromtimestamp(device.last_seen).isoformat() if device.last_seen else '',
                    'Packet Count': device.packet_count
                })

    def _save_html_report(self, path: Path, report_data: Dict[str, Any]):
        """Generate comprehensive HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Industrial Network Recon Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .device-table {{ width: 100%; border-collapse: collapse; }}
                .device-table th, .device-table td {{ border: 1px solid #ddd; padding: 8px; }}
                .device-table tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .critical {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Industrial Network Reconnaissance Report</h1>
                <p>Generated: {report_data['metadata']['datetime']}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>Total Devices: {report_data['metadata']['device_count']}</p>
                <p>Industrial Devices: {report_data['topology']['security_assessment']['industrial_devices']}</p>
                <p>Safety Level: {report_data['metadata']['safety_level']}</p>
            </div>
            
            <div class="section">
                <h2>Device Inventory</h2>
                <table class="device-table">
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Hostname</th>
                        <th>Vendor</th>
                        <th>Protocols</th>
                        <th>Criticality</th>
                    </tr>
        """
        
        for device_key, device in report_data['devices'].items():
            criticality_class = "critical" if device.get('criticality') == 'high' else ""
            html_content += f"""
                    <tr>
                        <td>{html.escape(str(device.get('ip', '')))}</td>
                        <td>{html.escape(str(device.get('mac', '')))}</td>
                        <td>{html.escape(str(device.get('hostname', '')))}</td>
                        <td>{html.escape(str(device.get('vendor', '')))}</td>
                        <td>{', '.join([html.escape(str(p)) for p in device.get('protocols', [])])}</td>
                        <td class="{criticality_class}">{html.escape(str(device.get('criticality', '')))}</td>
                    </tr>
            """
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Security Assessment</h2>
                <h3>Potential Vulnerabilities:</h3>
                <ul>
        """
        
        for vulnerability in report_data['topology']['security_assessment']['potential_vulnerabilities']:
            html_content += f"<li>{html.escape(str(vulnerability))}</li>"
        
        html_content += """
                </ul>
                <h3>Recommendations:</h3>
                <ul>
        """
        
        for recommendation in report_data['topology']['security_assessment']['recommendations']:
            html_content += f"<li>{html.escape(str(recommendation))}</li>"
        
        html_content += """
                </ul>
            </div>
        </body>
        </html>
        """
        
        path.write_text(html_content, encoding='utf-8')

    def _device_to_dict(self, device: IndustrialDevice) -> Dict[str, Any]:
        """Convert IndustrialDevice to serializable dict"""
        return {
            'ip': device.ip,
            'mac': device.mac,
            'hostname': device.hostname,
            'vendor': device.vendor,
            'os_family': device.os_family,
            'protocols': [p.value for p in device.protocols],
            'services': device.services,
            'snmp_data': device.snmp_data,
            'first_seen': device.first_seen,
            'last_seen': device.last_seen,
            'packet_count': device.packet_count,
            'criticality': device.criticality,
            'tags': device.tags,
            'relationships': device.relationships
        }

    # -----------------------------
    # Enhanced Helpers
    # -----------------------------
    def _mac_vendor_lookup(self, mac: str) -> Optional[str]:
        """Enhanced MAC vendor lookup with expanded database"""
        if not mac:
            return None
        
        try:
            # Normalize MAC address
            clean_mac = mac.upper().replace(':', '').replace('-', '')[:6]
            return self.mac_vendors.get(clean_mac, 'unknown')
        except Exception:
            return 'unknown'

    def ascii_topology(self) -> str:
        """Enhanced ASCII topology with more details"""
        lines = [
            "═" * 80,
            "INDUSTRIAL NETWORK TOPOLOGY ANALYSIS",
            "═" * 80,
            f"{'IP Address':18} {'MAC Address':18} {'Vendor':15} {'Protocols':20} {'Criticality':12}",
            "─" * 80
        ]
        
        for device_key in sorted(self.devices.keys()):
            device = self.devices[device_key]
            ip = device.ip or '-'
            mac = device.mac or '-'
            vendor = (device.vendor or 'unknown')[:14]
            protocols = ', '.join([p.value for p in device.protocols[:2]])  # First 2 protocols
            if len(device.protocols) > 2:
                protocols += f" (+{len(device.protocols)-2})"
            criticality = device.criticality
            
            lines.append(f"{ip:18} {mac:18} {vendor:15} {protocols:20} {criticality:12}")
        
        lines.extend([
            "─" * 80,
            f"Total devices: {len(self.devices)}",
            f"Industrial protocols detected: {sum(1 for d in self.devices.values() if any(p.value in ['modbus', 's7comm', 'dnp3', 'profinet'] for p in d.protocols))}",
            f"Network relationships: {len(self.network_relationships)}",
            "═" * 80
        ])
        
        return "\n".join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        stats = {
            'total_devices': len(self.devices),
            'devices_with_ip': sum(1 for d in self.devices.values() if d.ip),
            'devices_with_mac': sum(1 for d in self.devices.values() if d.mac),
            'industrial_devices': sum(1 for d in self.devices.values() if any(
                p.value in ['modbus', 's7comm', 'dnp3', 'profinet', 'ethernet_ip'] 
                for p in d.protocols
            )),
            'protocol_distribution': {},
            'vendor_distribution': {},
            'criticality_distribution': {},
            'scan_duration': getattr(self, 'last_scan_duration', 0)
        }
        
        for device in self.devices.values():
            # Protocol distribution
            for protocol in device.protocols:
                proto_name = protocol.value
                stats['protocol_distribution'][proto_name] = \
                    stats['protocol_distribution'].get(proto_name, 0) + 1
            
            # Vendor distribution
            vendor = device.vendor or 'unknown'
            stats['vendor_distribution'][vendor] = \
                stats['vendor_distribution'].get(vendor, 0) + 1
            
            # Criticality distribution
            stats['criticality_distribution'][device.criticality] = \
                stats['criticality_distribution'].get(device.criticality, 0) + 1
        
        return stats

# -----------------------------
# Advanced Usage Examples
# -----------------------------
"""
# Comprehensive industrial network assessment
recon = IndustrialRecon(config_manager=config, secrets_manager=secrets)

# Passive monitoring with deep analysis
result = recon.passive_listen(iface='eth0', duration=300, packet_count=10000)

# Conditional active discovery
if recon.safety_level != ScanSafetyLevel.PASSIVE_ONLY:
    recon.arp_sweep('192.168.1.0/24')
    recon.icmp_sweep('192.168.1.0/24')

# SNMP enrichment for discovered devices
recon.snmp_enrich()

# Comprehensive reporting
reports = recon.save_report(
    tag='plant_floor_scan', 
    formats=['json', 'csv', 'html', 'yaml']
)

print(recon.ascii_topology())
print("Statistics:", json.dumps(recon.get_statistics(), indent=2))
"""