# core/opcodes.py
import struct

# Tabela imutável de blocagem para IA externa
EXTERNAL_AI_BLOCKLIST = frozenset([0x60, 0x61, 0xF0, 0xFE, 0xFF])

# Opcodes que exigem permissão explícita do utilizador (Sim*)[cite: 14]
CONSENT_REQUIRED = frozenset([0x30, 0x31, 0x32, 0x33, 0x34, 0x40, 0x41])

class Flags:
    PRIVILEGED = 0x01

# Formato fixo e ultraleve de 8 bytes (64 bits, big-endian)
_INSTR_STRUCT = struct.Struct('>BBIH')

def encode_instruction(opcode, flags, key, value=0) -> bytes:
    """Codifica a instrução em exatamente 8 bytes big-endian (Seção 13.3)[cite: 10, 26]."""
    return _INSTR_STRUCT.pack(opcode, flags, key, value)

def decode_instruction(data: bytes) -> tuple:
    """Desempacota os 8 bytes da instrução em O(1) (Seção 13.3)[cite: 10, 26]."""
    if len(data) != 8:
        raise ValueError(f'Expected 8 bytes, got {len(data)}')
    return _INSTR_STRUCT.unpack(data)