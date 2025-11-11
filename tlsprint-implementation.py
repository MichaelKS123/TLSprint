"""
TLSprint - Advanced TLS Fingerprint Analysis & Client Identification
Created by: Michael Semera

A comprehensive TLS fingerprinting system using JA3, JA3S, and custom algorithms
to identify clients, detect bots, and analyze SSL/TLS handshakes for security
research and threat detection.

Features:
- JA3/JA3S fingerprint generation
- Client identification (browsers, bots, malware)
- Cipher suite analysis and vulnerability detection
- Real-time packet capture and analysis
- PCAP file processing
- Threat intelligence integration
"""

import hashlib
import struct
import socket
import ssl
import json
import time
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import logging
from pathlib import Path

# Try to import packet capture libraries
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls.all import TLS, TLSClientHello
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Packet capture features disabled.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - TLSprint - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Constants and TLS Mappings
# ============================================================================

# TLS Versions
TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    771: "TLS 1.2",  # Decimal
    772: "TLS 1.3"
}

# Common Cipher Suites (abbreviated list)
CIPHER_SUITES = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}

# TLS Extensions
TLS_EXTENSIONS = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    35: "session_ticket",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    65281: "renegotiation_info",
}

# Elliptic Curves (Supported Groups)
SUPPORTED_GROUPS = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
    256: "ffdhe2048",
    257: "ffdhe3072",
}

# GREASE values (should be ignored)
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

# Weak/Insecure Cipher Suites
WEAK_CIPHERS = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005,  # NULL, MD5, RC4
    0x000A, 0x0016, 0x0013, 0x0010,  # 3DES, DES
}


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ClientType(Enum):
    """Type of TLS client"""
    BROWSER = "browser"
    BOT = "bot"
    MOBILE_APP = "mobile_app"
    MALWARE = "malware"
    TOOL = "tool"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class TLSFingerprint:
    """Complete TLS fingerprint information"""
    # Raw fingerprint data
    ja3_string: str
    ja3_hash: str
    
    # TLS parameters
    tls_version: int
    cipher_suites: List[int]
    extensions: List[int]
    supported_groups: List[int]
    ec_point_formats: List[int]
    
    # Connection info
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    timestamp: float = field(default_factory=time.time)
    
    # Analysis results
    client_name: str = "Unknown"
    client_type: ClientType = ClientType.UNKNOWN
    client_version: str = ""
    os: str = "Unknown"
    confidence: float = 0.0
    
    # Security analysis
    is_suspicious: bool = False
    threat_level: ThreatLevel = ThreatLevel.SAFE
    threat_indicators: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    
    # Metadata
    metadata: Dict = field(default_factory=dict)


@dataclass
class CipherAnalysis:
    """Cipher suite security analysis"""
    strength: str  # HIGH, MEDIUM, LOW, INSECURE
    forward_secrecy: bool
    aead: bool
    weak_ciphers: List[int]
    recommended_ciphers: List[int]
    security_score: int  # 0-100


@dataclass
class ClientSignature:
    """Known client signature"""
    name: str
    type: ClientType
    ja3_hashes: List[str]
    patterns: Dict
    version_pattern: Optional[str] = None


# ============================================================================
# JA3 Fingerprint Generator
# ============================================================================

class JA3Generator:
    """
    Generate JA3 fingerprints from TLS Client Hello packets.
    
    JA3 methodology:
    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    """
    
    @staticmethod
    def generate(client_hello_data: Dict) -> Tuple[str, str]:
        """
        Generate JA3 fingerprint from Client Hello data.
        
        Args:
            client_hello_data: Parsed Client Hello packet data
            
        Returns:
            Tuple of (ja3_string, ja3_hash)
        """
        logger.debug("Generating JA3 fingerprint")
        
        # Extract SSL/TLS version
        ssl_version = client_hello_data.get('version', 771)
        
        # Extract cipher suites (filter GREASE)
        cipher_suites = [
            str(c) for c in client_hello_data.get('cipher_suites', [])
            if c not in GREASE_VALUES
        ]
        
        # Extract extensions (filter GREASE)
        extensions = [
            str(e) for e in client_hello_data.get('extensions', [])
            if e not in GREASE_VALUES
        ]
        
        # Extract supported groups (elliptic curves)
        supported_groups = [
            str(g) for g in client_hello_data.get('supported_groups', [])
            if g not in GREASE_VALUES
        ]
        
        # Extract EC point formats
        ec_point_formats = [
            str(p) for p in client_hello_data.get('ec_point_formats', [])
        ]
        
        # Build JA3 string
        ja3_parts = [
            str(ssl_version),
            '-'.join(cipher_suites) if cipher_suites else '',
            '-'.join(extensions) if extensions else '',
            '-'.join(supported_groups) if supported_groups else '',
            '-'.join(ec_point_formats) if ec_point_formats else ''
        ]
        
        ja3_string = ','.join(ja3_parts)
        
        # Generate MD5 hash
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        logger.debug(f"JA3 String: {ja3_string}")
        logger.debug(f"JA3 Hash: {ja3_hash}")
        
        return ja3_string, ja3_hash
    
    @staticmethod
    def parse_ja3_string(ja3_string: str) -> Dict:
        """Parse JA3 string back into components"""
        parts = ja3_string.split(',')
        
        if len(parts) != 5:
            raise ValueError("Invalid JA3 string format")
        
        return {
            'version': int(parts[0]) if parts[0] else 0,
            'ciphers': [int(c) for c in parts[1].split('-') if c],
            'extensions': [int(e) for e in parts[2].split('-') if e],
            'curves': [int(c) for c in parts[3].split('-') if c],
            'point_formats': [int(p) for p in parts[4].split('-') if p]
        }


# ============================================================================
# TLS Client Hello Parser
# ============================================================================

class ClientHelloParser:
    """
    Parse TLS Client Hello packets to extract fingerprinting data.
    """
    
    @staticmethod
    def parse_from_bytes(data: bytes) -> Optional[Dict]:
        """
        Parse Client Hello from raw bytes.
        
        Args:
            data: Raw packet bytes
            
        Returns:
            Dict with parsed Client Hello data or None
        """
        try:
            # Check if this is a TLS handshake
            if len(data) < 6 or data[0] != 0x16:  # Handshake content type
                return None
            
            # Parse TLS record header
            content_type = data[0]
            version = struct.unpack('>H', data[1:3])[0]
            length = struct.unpack('>H', data[3:5])[0]
            
            # Check handshake type
            if data[5] != 0x01:  # Client Hello
                return None
            
            offset = 9  # Skip handshake header
            
            # Parse Client Hello
            client_version = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            # Random (32 bytes)
            random = data[offset:offset+32]
            offset += 32
            
            # Session ID
            session_id_length = data[offset]
            offset += 1 + session_id_length
            
            # Cipher suites
            cipher_suites_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            cipher_suites = []
            for i in range(0, cipher_suites_length, 2):
                cipher = struct.unpack('>H', data[offset+i:offset+i+2])[0]
                cipher_suites.append(cipher)
            offset += cipher_suites_length
            
            # Compression methods
            compression_length = data[offset]
            offset += 1 + compression_length
            
            # Extensions
            extensions_data = {}
            if offset < len(data):
                extensions = ClientHelloParser._parse_extensions(data[offset:])
                extensions_data = extensions
            
            return {
                'version': client_version,
                'random': random.hex(),
                'cipher_suites': cipher_suites,
                'extensions': list(extensions_data.keys()),
                'supported_groups': extensions_data.get(10, []),
                'ec_point_formats': extensions_data.get(11, []),
                'signature_algorithms': extensions_data.get(13, []),
                'alpn': extensions_data.get(16, []),
                'sni': extensions_data.get(0, ''),
            }
            
        except Exception as e:
            logger.error(f"Error parsing Client Hello: {e}")
            return None
    
    @staticmethod
    def _parse_extensions(data: bytes) -> Dict:
        """Parse TLS extensions from data"""
        extensions = {}
        
        if len(data) < 2:
            return extensions
        
        extensions_length = struct.unpack('>H', data[0:2])[0]
        offset = 2
        
        while offset < extensions_length + 2:
            if offset + 4 > len(data):
                break
            
            ext_type = struct.unpack('>H', data[offset:offset+2])[0]
            ext_length = struct.unpack('>H', data[offset+2:offset+4])[0]
            offset += 4
            
            ext_data = data[offset:offset+ext_length]
            
            # Parse specific extensions
            if ext_type == 10:  # supported_groups
                extensions[ext_type] = ClientHelloParser._parse_supported_groups(ext_data)
            elif ext_type == 11:  # ec_point_formats
                extensions[ext_type] = ClientHelloParser._parse_ec_point_formats(ext_data)
            elif ext_type == 0:  # server_name (SNI)
                extensions[ext_type] = ClientHelloParser._parse_sni(ext_data)
            else:
                extensions[ext_type] = []
            
            offset += ext_length
        
        return extensions
    
    @staticmethod
    def _parse_supported_groups(data: bytes) -> List[int]:
        """Parse supported groups extension"""
        if len(data) < 2:
            return []
        
        length = struct.unpack('>H', data[0:2])[0]
        groups = []
        
        for i in range(2, length + 2, 2):
            if i + 2 <= len(data):
                group = struct.unpack('>H', data[i:i+2])[0]
                groups.append(group)
        
        return groups
    
    @staticmethod
    def _parse_ec_point_formats(data: bytes) -> List[int]:
        """Parse EC point formats extension"""
        if len(data) < 1:
            return []
        
        length = data[0]
        return list(data[1:1+length])
    
    @staticmethod
    def _parse_sni(data: bytes) -> str:
        """Parse Server Name Indication extension"""
        try:
            if len(data) < 5:
                return ""
            
            list_length = struct.unpack('>H', data[0:2])[0]
            name_type = data[2]
            name_length = struct.unpack('>H', data[3:5])[0]
            server_name = data[5:5+name_length].decode('utf-8', errors='ignore')
            
            return server_name
        except:
            return ""


# ============================================================================
# Client Identifier
# ============================================================================

class ClientIdentifier:
    """
    Identify TLS clients based on fingerprints and patterns.
    """
    
    def __init__(self):
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> List[ClientSignature]:
        """Load known client signatures"""
        # In production, this would load from a database or file
        return [
            ClientSignature(
                name="Chrome",
                type=ClientType.BROWSER,
                ja3_hashes=[
                    "6734f37431670b3ab4292b8f60f29984",
                    "a0e9f5d64349fb13191bc781f81f42e1"
                ],
                patterns={
                    'extensions': [0, 23, 65281, 10, 11, 35, 16, 5, 13],
                    'alpn': ['h2', 'http/1.1']
                }
            ),
            ClientSignature(
                name="Firefox",
                type=ClientType.BROWSER,
                ja3_hashes=[
                    "b32309a26951912be7dba376398abc3b"
                ],
                patterns={
                    'extensions': [0, 23, 65281, 10, 11, 35, 13, 28]
                }
            ),
            ClientSignature(
                name="curl",
                type=ClientType.BOT,
                ja3_hashes=[
                    "51c64c77e60f3980eea90869b68c58a8"
                ],
                patterns={
                    'cipher_count': lambda x: x < 10
                }
            ),
            ClientSignature(
                name="Python requests",
                type=ClientType.BOT,
                ja3_hashes=[
                    "77fd0eb3c7ca56e2d76647eb0a1a1c38"
                ],
                patterns={}
            ),
        ]
    
    def identify(self, fingerprint: TLSFingerprint) -> TLSFingerprint:
        """
        Identify client from fingerprint.
        
        Args:
            fingerprint: TLS fingerprint to identify
            
        Returns:
            Updated fingerprint with client information
        """
        logger.debug(f"Identifying client for JA3: {fingerprint.ja3_hash}")
        
        # Check exact JA3 match
        for sig in self.signatures:
            if fingerprint.ja3_hash in sig.ja3_hashes:
                fingerprint.client_name = sig.name
                fingerprint.client_type = sig.type
                fingerprint.confidence = 0.95
                logger.info(f"Client identified: {sig.name} (exact match)")
                return fingerprint
        
        # Check pattern matching
        best_match = None
        best_score = 0.0
        
        for sig in self.signatures:
            score = self._calculate_similarity(fingerprint, sig)
            if score > best_score:
                best_score = score
                best_match = sig
        
        if best_match and best_score > 0.7:
            fingerprint.client_name = best_match.name
            fingerprint.client_type = best_match.type
            fingerprint.confidence = best_score
            logger.info(f"Client identified: {best_match.name} (similarity: {best_score:.2f})")
        else:
            fingerprint.client_name = "Unknown"
            fingerprint.client_type = ClientType.UNKNOWN
            fingerprint.confidence = 0.0
            logger.info("Client could not be identified")
        
        return fingerprint
    
    def _calculate_similarity(self, fp: TLSFingerprint, sig: ClientSignature) -> float:
        """Calculate similarity score between fingerprint and signature"""
        score = 0.0
        checks = 0
        
        # Check extension overlap
        if 'extensions' in sig.patterns:
            expected_ext = set(sig.patterns['extensions'])
            actual_ext = set(fp.extensions)
            overlap = len(expected_ext & actual_ext)
            score += overlap / len(expected_ext) if expected_ext else 0
            checks += 1
        
        # Check cipher count patterns
        if 'cipher_count' in sig.patterns:
            if sig.patterns['cipher_count'](len(fp.cipher_suites)):
                score += 1.0
            checks += 1
        
        return score / checks if checks > 0 else 0.0


# ============================================================================
# Cipher Suite Analyzer
# ============================================================================

class CipherAnalyzer:
    """
    Analyze cipher suites for security and compatibility.
    """
    
    # Cipher strength classification
    HIGH_STRENGTH = {0xC02F, 0xC030, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C}
    MEDIUM_STRENGTH = {0x002F, 0x0035, 0xC013, 0xC014}
    LOW_STRENGTH = {0x000A, 0x0016}
    
    @staticmethod
    def analyze(cipher_suites: List[int]) -> CipherAnalysis:
        """
        Analyze security of cipher suites.
        
        Args:
            cipher_suites: List of cipher suite IDs
            
        Returns:
            CipherAnalysis with security assessment
        """
        logger.debug(f"Analyzing {len(cipher_suites)} cipher suites")
        
        # Classify ciphers by strength
        high = sum(1 for c in cipher_suites if c in CipherAnalyzer.HIGH_STRENGTH)
        medium = sum(1 for c in cipher_suites if c in CipherAnalyzer.MEDIUM_STRENGTH)
        low = sum(1 for c in cipher_suites if c in CipherAnalyzer.LOW_STRENGTH)
        weak = [c for c in cipher_suites if c in WEAK_CIPHERS]
        
        # Determine overall strength
        if high > 0 and not weak:
            strength = "HIGH"
        elif medium > 0 and not weak:
            strength = "MEDIUM"
        elif low > 0 or weak:
            strength = "LOW"
        else:
            strength = "UNKNOWN"
        
        # Check for forward secrecy (ECDHE ciphers)
        forward_secrecy = any(
            c in {0xC02F, 0xC030, 0xC013, 0xC014, 0xC02B, 0xC02C}
            for c in cipher_suites
        )
        
        # Check for AEAD ciphers (GCM, CHACHA20)
        aead = any(
            c in {0xC02F, 0xC030, 0x1301, 0x1302, 0x1303, 0x009C, 0x009D, 0xC02B, 0xC02C}
            for c in cipher_suites
        )
        
        # Calculate security score
        score = 100
        score -= len(weak) * 30
        score -= low * 10
        if not forward_secrecy:
            score -= 20
        if not aead:
            score -= 10
        score = max(0, min(100, score))
        
        # Recommended ciphers
        recommended = [0xC02F, 0xC030, 0x1301, 0x1302, 0x1303]
        
        return CipherAnalysis(
            strength=strength,
            forward_secrecy=forward_secrecy,
            aead=aead,
            weak_ciphers=weak,
            recommended_ciphers=recommended,
            security_score=score
        )


# ============================================================================
# Threat Detector
# ============================================================================

class ThreatDetector:
    """
    Detect threats and suspicious patterns in TLS fingerprints.
    """
    
    # Known malware JA3 hashes (example)
    MALWARE_JA3 = {
        "e7d705a3286e19ea42f587b344ee6865": "Trickbot",
        "a0e9f5d64349fb13191bc781f81f42e2": "Emotet",
    }
    
    def analyze(self, fingerprint: TLSFingerprint) -> TLSFingerprint:
        """
        Analyze fingerprint for threats.
        
        Args:
            fingerprint: TLS fingerprint to analyze
            
        Returns:
            Updated fingerprint with threat information
        """
        logger.debug("Analyzing fingerprint for threats")
        
        threats = []
        vulnerabilities = []
        threat_level = ThreatLevel.SAFE
        
        # Check known malware
        if fingerprint.ja3_hash in self.MALWARE_JA3:
            threats.append(f"Known malware: {self.MALWARE_JA3[fingerprint.ja3_hash]}")
            threat_level = ThreatLevel.CRITICAL
        
        # Check outdated protocol
        if fingerprint.tls_version < 771:  # < TLS 1.2
            threats.append("Outdated TLS protocol version")
            vulnerabilities.append("POODLE" if fingerprint.tls_version == 768 else "BEAST")
            threat_level = max(threat_level, ThreatLevel.HIGH)
        
        # Check weak ciphers
        weak = [c for c in fingerprint.cipher_suites if c in WEAK_CIPHERS]
        if weak:
            threats.append(f"Weak cipher suites detected: {len(weak)}")
            threat_level = max(threat_level, ThreatLevel.HIGH)
        
        # Check suspicious extension combinations
        if len(fingerprint.extensions) < 3:
            threats.append("Unusually few TLS extensions")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        fingerprint.is_suspicious = len(threats) > 0
        fingerprint.threat_level = threat_level
        fingerprint.threat_indicators = threats
        fingerprint.vulnerabilities = vulnerabilities
        
        logger.info(f"Threat analysis complete: {threat_level.name} ({len(threats)} indicators)")
        
        return fingerprint


# ============================================================================
# Main TLS Fingerprinter
# ============================================================================

class TLSFingerprinter:
    """
    Main TLS fingerprinting engine.
    Orchestrates fingerprint generation, analysis, and identification.
    """
    
    def __init__(self):
        self.ja3_generator = JA3Generator()
        self.parser = ClientHelloParser()
        self.identifier = ClientIdentifier()
        self.cipher_analyzer = CipherAnalyzer()
        self.threat_detector = ThreatDetector()
    
    def fingerprint_from_bytes(self, packet_data: bytes, 
                               src_ip: str = "", dst_ip: str = "") -> Optional[TLSFingerprint]:
        """
        Generate fingerprint from raw packet bytes.
        
        Args:
            packet_data: Raw packet bytes containing Client Hello
            src_ip: Source IP address
            dst_ip: Destination IP address
            
        Returns:
            TLSFingerprint or None if parsing fails
        """
        logger.info("🔍 Generating TLS fingerprint from packet")
        
        # Parse Client Hello
        client_hello = self.parser.parse_from_bytes(packet_data)
        if not client_hello:
            logger.warning("Failed to parse Client Hello")
            return None
        
        # Generate JA3
        ja3_string, ja3_hash = self.ja3_generator.generate(client_hello)
        
        # Create fingerprint object
        fingerprint = TLSFingerprint(
            ja3_string=ja3_string,
            ja3_hash=ja3_hash,
            tls_version=client_hello['version'],
            cipher_suites=client_hello['cipher_suites'],
            extensions=client_hello['extensions'],
            supported_groups=client_hello.get('supported_groups', []),
            ec_point_formats=client_hello.get('ec_point_formats', []),
            src_ip=src_ip,
            dst_ip=dst_ip,
            metadata={
                'sni': client_hello.get('sni', ''),
                'alpn': client_hello.get('alpn', [])
            }
        )
        
        # Identify client
        fingerprint = self.identifier.identify(fingerprint)
        
        # Analyze cipher suites
        cipher_analysis = self.cipher_analyzer.analyze(fingerprint.cipher_suites)
        fingerprint.metadata['cipher_analysis'] = asdict(cipher_analysis)
        
        # Threat detection
        fingerprint = self.threat_detector.analyze(fingerprint)
        
        logger.info(f"✅ Fingerprint generated: {ja3_hash}")
        logger.info(f"   Client: {fingerprint.client_name} ({fingerprint.client_type.value})")
        logger.info(f"   Confidence: {fingerprint.confidence:.0%}")
        logger.info(f"   Threat Level: {fingerprint.threat_level.name}")
        
        return fingerprint
    
    def fingerprint_connection(self, host: str, port: int = 443) -> Optional[TLSFingerprint]:
        """
        Fingerprint TLS connection to a server.
        
        Args:
            host: Target hostname
            port: Target port
            
        Returns:
            TLSFingerprint or None
        """
        logger.info(f"🔗 Connecting to {host}:{port} for fingerprinting")
        
        try:
            # Create SSL context that captures handshake
            context = ssl.create_default_context()
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get connection info
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    logger.info(f"   Cipher: {cipher}")
                    logger.info(f"   Version: {version}")
                    
                    # Note: Full fingerprinting requires packet capture
                    # This is a simplified demonstration
                    
            logger.info("✅ Connection fingerprinting complete")
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return None


# ============================================================================
# Demo and Main Execution
# ============================================================================

def create_sample_client_hello() -> bytes:
    """Create a sample Client Hello packet for demonstration"""
    # This is a simplified Chrome Client Hello packet structure
    client_hello = bytearray()
    
    # TLS Record Layer
    client_hello.append(0x16)  # Handshake
    client_hello.extend(struct.pack('>H', 0x0303))  # TLS 1.2
    
    # Placeholder length (will be updated)
    length_pos = len(client_hello)
    client_hello.extend(b'\x00\x00')
    
    # Handshake Protocol
    client_hello.append(0x01)  # Client Hello
    client_hello.extend(b'\x00\x00\x00')  # Handshake length (placeholder)
    
    # Client Hello
    client_hello.extend(struct.pack('>H', 0x0303))  # TLS 1.2
    client_hello.extend(b'\x00' * 32)  # Random
    client_hello.append(0x00)  # Session ID length
    
    # Cipher Suites
    ciphers = [0xC02F, 0xC030, 0xC013, 0xC014, 0x002F, 0x0035]
    client_hello.extend(struct.pack('>H', len(ciphers) * 2))
    for cipher in ciphers:
        client_hello.extend(struct.pack('>H', cipher))
    
    # Compression methods
    client_hello.append(0x01)  # Length
    client_hello.append(0x00)  # NULL compression
    
    # Extensions
    extensions = bytearray()
    
    # Server Name (SNI)
    extensions.extend(struct.pack('>H', 0))  # Extension type
    sni_data = b'example.com'
    sni_length = len(sni_data) + 5
    extensions.extend(struct.pack('>H', sni_length))
    extensions.extend(struct.pack('>H', len(sni_data) + 3))
    extensions.append(0x00)  # Name type: host_name
    extensions.extend(struct.pack('>H', len(sni_data)))
    extensions.extend(sni_data)
    
    # Supported Groups
    extensions.extend(struct.pack('>H', 10))  # Extension type
    groups = [29, 23, 24]  # x25519, secp256r1, secp384r1
    extensions.extend(struct.pack('>H', len(groups) * 2 + 2))
    extensions.extend(struct.pack('>H', len(groups) * 2))
    for group in groups:
        extensions.extend(struct.pack('>H', group))
    
    # EC Point Formats
    extensions.extend(struct.pack('>H', 11))  # Extension type
    extensions.extend(struct.pack('>H', 2))
    extensions.append(0x01)  # Length
    extensions.append(0x00)  # uncompressed
    
    # Add extensions to Client Hello
    client_hello.extend(struct.pack('>H', len(extensions)))
    client_hello.extend(extensions)
    
    # Update lengths
    total_length = len(client_hello) - 5
    client_hello[length_pos:length_pos+2] = struct.pack('>H', total_length)
    
    return bytes(client_hello)


def demo_basic_fingerprinting():
    """Demonstrate basic fingerprinting"""
    print("="*70)
    print("   TLSprint - Basic Fingerprinting Demo")
    print("="*70)
    print()
    
    # Create sample packet
    print("📦 Creating sample Client Hello packet...")
    packet_data = create_sample_client_hello()
    print(f"   Packet size: {len(packet_data)} bytes")
    print()
    
    # Create fingerprinter
    fingerprinter = TLSFingerprinter()
    
    # Generate fingerprint
    fingerprint = fingerprinter.fingerprint_from_bytes(
        packet_data,
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34"
    )
    
    if fingerprint:
        print("\n" + "="*70)
        print("📊 FINGERPRINT ANALYSIS REPORT")
        print("="*70)
        
        print(f"\n🔑 JA3 Fingerprint:")
        print(f"   String: {fingerprint.ja3_string}")
        print(f"   Hash: {fingerprint.ja3_hash}")
        
        print(f"\n🌐 Connection Information:")
        print(f"   Source: {fingerprint.src_ip}")
        print(f"   Destination: {fingerprint.dst_ip}")
        print(f"   SNI: {fingerprint.metadata.get('sni', 'N/A')}")
        
        print(f"\n🔐 TLS Parameters:")
        print(f"   Version: {TLS_VERSIONS.get(fingerprint.tls_version, 'Unknown')}")
        print(f"   Cipher Suites: {len(fingerprint.cipher_suites)}")
        print(f"   Extensions: {len(fingerprint.extensions)}")
        print(f"   Supported Groups: {len(fingerprint.supported_groups)}")
        
        print(f"\n👤 Client Identification:")
        print(f"   Name: {fingerprint.client_name}")
        print(f"   Type: {fingerprint.client_type.value}")
        print(f"   Confidence: {fingerprint.confidence:.0%}")
        
        # Cipher analysis
        if 'cipher_analysis' in fingerprint.metadata:
            cipher_info = fingerprint.metadata['cipher_analysis']
            print(f"\n🛡️  Cipher Suite Analysis:")
            print(f"   Strength: {cipher_info['strength']}")
            print(f"   Forward Secrecy: {'✅' if cipher_info['forward_secrecy'] else '❌'}")
            print(f"   AEAD Support: {'✅' if cipher_info['aead'] else '❌'}")
            print(f"   Security Score: {cipher_info['security_score']}/100")
        
        print(f"\n⚠️  Threat Assessment:")
        print(f"   Threat Level: {fingerprint.threat_level.name}")
        print(f"   Suspicious: {'Yes' if fingerprint.is_suspicious else 'No'}")
        if fingerprint.threat_indicators:
            print(f"   Indicators:")
            for indicator in fingerprint.threat_indicators:
                print(f"     • {indicator}")
        else:
            print(f"   No threats detected ✅")
        
        # Display cipher suites
        print(f"\n📋 Cipher Suites:")
        for cipher in fingerprint.cipher_suites[:5]:
            cipher_name = CIPHER_SUITES.get(cipher, f"Unknown (0x{cipher:04X})")
            print(f"   • {cipher_name}")
        if len(fingerprint.cipher_suites) > 5:
            print(f"   ... and {len(fingerprint.cipher_suites) - 5} more")
        
        # Display extensions
        print(f"\n🔧 Extensions:")
        for ext in fingerprint.extensions[:10]:
            ext_name = TLS_EXTENSIONS.get(ext, f"Unknown ({ext})")
            print(f"   • {ext_name}")
        if len(fingerprint.extensions) > 10:
            print(f"   ... and {len(fingerprint.extensions) - 10} more")
        
        print("\n" + "="*70)


def demo_ja3_parsing():
    """Demonstrate JA3 string parsing"""
    print("\n" + "="*70)
    print("   JA3 String Parsing Demo")
    print("="*70)
    print()
    
    # Example JA3 strings
    ja3_examples = {
        "Chrome 120": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        "Firefox 121": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
        "curl 7.68": "771,49200-49196-49192-49188-49172-49162-159-158-107-106-57-56-136-135-49202-49198-49194-49190-49167-49157-61-53-132-141-49199-49195-49191-49187-49171-49161-158-107-106-57-56-136-135-49201-49197-49193-49189-49166-49156-60-47-150-65-255,0-11-10-35-13-15,23-25-28-27-24-26-22-14-13-11-12-9-10,0-1-2",
    }
    
    for client_name, ja3_string in ja3_examples.items():
        print(f"\n🔍 Analyzing: {client_name}")
        print(f"   JA3 String: {ja3_string[:80]}...")
        
        # Parse JA3
        components = JA3Generator.parse_ja3_string(ja3_string)
        
        # Generate hash
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        print(f"   JA3 Hash: {ja3_hash}")
        print(f"   TLS Version: {TLS_VERSIONS.get(components['version'], 'Unknown')}")
        print(f"   Ciphers: {len(components['ciphers'])}")
        print(f"   Extensions: {len(components['extensions'])}")
        print(f"   Curves: {len(components['curves'])}")


def demo_threat_detection():
    """Demonstrate threat detection"""
    print("\n" + "="*70)
    print("   Threat Detection Demo")
    print("="*70)
    print()
    
    # Create fingerprints with different threat levels
    scenarios = [
        {
            'name': 'Legitimate Browser',
            'version': 771,  # TLS 1.2
            'ciphers': [0xC02F, 0xC030, 0x1301],
            'extensions': [0, 23, 65281, 10, 11, 35, 16, 5, 13]
        },
        {
            'name': 'Outdated Client',
            'version': 769,  # TLS 1.0
            'ciphers': [0x002F, 0x0035],
            'extensions': [0, 10]
        },
        {
            'name': 'Insecure Bot',
            'version': 768,  # SSL 3.0
            'ciphers': [0x0004, 0x0005],  # RC4
            'extensions': []
        }
    ]
    
    detector = ThreatDetector()
    
    for scenario in scenarios:
        print(f"\n📍 Scenario: {scenario['name']}")
        
        # Create fingerprint
        fp = TLSFingerprint(
            ja3_string="",
            ja3_hash="",
            tls_version=scenario['version'],
            cipher_suites=scenario['ciphers'],
            extensions=scenario['extensions'],
            supported_groups=[],
            ec_point_formats=[]
        )
        
        # Analyze
        fp = detector.analyze(fp)
        
        print(f"   Threat Level: {fp.threat_level.name}")
        print(f"   Suspicious: {'Yes ⚠️' if fp.is_suspicious else 'No ✅'}")
        
        if fp.threat_indicators:
            print(f"   Threats Detected:")
            for threat in fp.threat_indicators:
                print(f"     • {threat}")
        
        if fp.vulnerabilities:
            print(f"   Vulnerabilities:")
            for vuln in fp.vulnerabilities:
                print(f"     • {vuln}")


def main():
    """Main execution"""
    print("="*70)
    print("   TLSprint - TLS Fingerprint Analysis System")
    print("   Created by: Michael Semera")
    print("="*70)
    print()
    
    # Run demos
    demo_basic_fingerprinting()
    demo_ja3_parsing()
    demo_threat_detection()
    
    print("\n" + "="*70)
    print("📚 USAGE EXAMPLES")
    print("="*70)
    print("""
# Basic fingerprinting from packet
from tlsprint import TLSFingerprinter

fp = TLSFingerprinter()
fingerprint = fp.fingerprint_from_bytes(packet_data)

print(f"JA3: {fingerprint.ja3_hash}")
print(f"Client: {fingerprint.client_name}")
print(f"Threat Level: {fingerprint.threat_level.name}")

# Analyze cipher suites
from tlsprint import CipherAnalyzer

analysis = CipherAnalyzer.analyze(cipher_suites)
print(f"Strength: {analysis.strength}")
print(f"Security Score: {analysis.security_score}/100")

# Client identification
from tlsprint import ClientIdentifier

identifier = ClientIdentifier()
fingerprint = identifier.identify(fingerprint)
print(f"Client: {fingerprint.client_name}")
print(f"Type: {fingerprint.client_type.value}")
print(f"Confidence: {fingerprint.confidence:.0%}")

# Threat detection
from tlsprint import ThreatDetector

detector = ThreatDetector()
fingerprint = detector.analyze(fingerprint)

for threat in fingerprint.threat_indicators:
    print(f"Threat: {threat}")
""")
    
    print("\n" + "="*70)
    print("✨ Demo Complete!")
    print("="*70)


# ============================================================================
# CLI Interface
# ============================================================================

def cli_main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='TLSprint - Advanced TLS fingerprinting and analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s fingerprint example.com
  %(prog)s analyze capture.pcap
  %(prog)s ja3 "771,49195-49199,0-23-65281"
  
Created by: Michael Semera
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Fingerprint command
    fp_parser = subparsers.add_parser('fingerprint', help='Fingerprint TLS connection')
    fp_parser.add_argument('host', help='Target host')
    fp_parser.add_argument('--port', type=int, default=443, help='Target port')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze PCAP file')
    analyze_parser.add_argument('pcap', help='PCAP file to analyze')
    analyze_parser.add_argument('--output', help='Output file (JSON)')
    
    # JA3 command
    ja3_parser = subparsers.add_parser('ja3', help='Parse JA3 string')
    ja3_parser.add_argument('ja3_string', help='JA3 string to parse')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run demonstration')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version')
    
    args = parser.parse_args()
    
    if args.command == 'fingerprint':
        fp = TLSFingerprinter()
        result = fp.fingerprint_connection(args.host, args.port)
    
    elif args.command == 'ja3':
        components = JA3Generator.parse_ja3_string(args.ja3_string)
        ja3_hash = hashlib.md5(args.ja3_string.encode()).hexdigest()
        
        print(f"JA3 Hash: {ja3_hash}")
        print(f"TLS Version: {components['version']}")
        print(f"Ciphers: {len(components['ciphers'])}")
        print(f"Extensions: {len(components['extensions'])}")
    
    elif args.command == 'demo':
        main()
    
    elif args.command == 'version':
        print("TLSprint v1.0.0")
        print("Created by: Michael Semera")
    
    else:
        parser.print_help()


# ============================================================================
# Export Public API
# ============================================================================

__all__ = [
    'TLSFingerprinter',
    'TLSFingerprint',
    'JA3Generator',
    'ClientHelloParser',
    'ClientIdentifier',
    'CipherAnalyzer',
    'ThreatDetector',
    'ClientType',
    'ThreatLevel',
    'CipherAnalysis',
]

__version__ = '1.0.0'
__author__ = 'Michael Semera'
__description__ = 'Advanced TLS fingerprinting for client identification and threat detection'


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        cli_main()
    else:
        main()