# tests/test_opcodes.py
"""
Suíte de testes unitários e de segurança para core/opcodes.py.
Cumpre os Critérios de Aceite da Sprint 0 (Seção 12.2 e 13.1).
"""
import struct
import pytest
from core.opcodes import (
    CONSENT_REQUIRED,
    EXTERNAL_AI_BLOCKLIST,
    Flags,
    Opcode,
    decode_instruction,
    encode_instruction,
)


def test_encode_decode_roundtrip_uber_example():
    """
    Valida o exemplo oficial da Seção 3.3 (Uber) e o critério de round-trip
    sem perda da Seção 12.2.
    """
    raw = encode_instruction(
        opcode=0x30,        # SYS_OPEN_APP
        flags=0x04,         # AUDITED
        key=0x0C000001,     # app=Uber, acao=setPickup
        value=0x004A,       # destino=aeroporto (ID local)
    )
    assert isinstance(raw, bytes)
    assert len(raw) == 8
    assert raw == bytes.fromhex("30040c000001004a")

    opcode, flags, key, value = decode_instruction(raw)
    assert opcode == 0x30
    assert flags == 0x04
    assert key == 0x0C000001
    assert value == 0x004A


def test_encode_instruction_default_value():
    """Testa o valor default value=0 definido na assinatura da Seção 13.3."""
    raw = encode_instruction(Opcode.NOP, 0x00, 0x00000001)
    assert decode_instruction(raw) == (Opcode.NOP, 0x00, 0x00000001, 0)


@pytest.mark.parametrize("invalid_data", [
    b"",
    b"\x00" * 7,
    b"\x00" * 9,
    b"\x30\x04\x0c",
])
def test_decode_instruction_rejects_invalid_length(invalid_data):
    """
    Garante que qualquer payload diferente de 8 bytes levanta ValueError
    conforme Seção 3.1 e 13.3.
    """
    with pytest.raises(ValueError, match=f"Expected 8 bytes, got {len(invalid_data)}"):
        decode_instruction(invalid_data)


@pytest.mark.parametrize("opcode,flags,key,value", [
    (256, 0, 0, 0),            # Estouro de 8 bits no opcode
    (-1, 0, 0, 0),             # Valor negativo no opcode
    (0, 256, 0, 0),            # Estouro de 8 bits em flags
    (0, 0, 0xFFFFFFFF + 1, 0), # Estouro de 32 bits em key
    (0, 0, 0, 0xFFFF + 1),     # Estouro de 16 bits em value
])
def test_encode_instruction_rejects_bit_overflow(opcode, flags, key, value):
    """Valida os limites estritos de 8, 8, 32 e 16 bits da Seção 3.2."""
    with pytest.raises(struct.error):
        encode_instruction(opcode, flags, key, value)


def test_external_ai_blocklist_security_coverage():
    """
    Audita se EXTERNAL_AI_BLOCKLIST é frozenset imutável e bloqueia todas as
    faixas proibidas nas Seções 5.2 e 7.1.
    """
    assert isinstance(EXTERNAL_AI_BLOCKLIST, frozenset)

    # Faixa 0x60-0x7F (Seção 5.2)
    for op in range(0x60, 0x80):
        assert op in EXTERNAL_AI_BLOCKLIST

    # Faixa reservada 0xF0+ (Seção 5.2, 7.1 e 13.4)
    for op in (0xF0, 0xFE, 0xFF):
        assert op in EXTERNAL_AI_BLOCKLIST

    # Opcodes internos marcados como 'Externo: Não / NÃO' na Tabela 7.1
    for op in (
        Opcode.HALT,
        Opcode.INFER,
        Opcode.MHA_HEAD,
        Opcode.GNN_LOOKUP,
        Opcode.GNN_PROPAGATE,
        Opcode.SOFTMAX,
        Opcode.SEC_AUDIT,
        Opcode.SEC_REVOKE,
    ):
        assert op in EXTERNAL_AI_BLOCKLIST

    # Opcodes permitidos para IA externa não devem estar bloqueados (Tabela 7.1)
    for op in (
        Opcode.NOP,
        Opcode.KV_GET,
        Opcode.KV_SET,
        Opcode.KV_DEL,
        Opcode.SYS_OPEN_APP,
        Opcode.SYS_NOTIFY,
        Opcode.SYS_QUERY_CTX,
        Opcode.SYS_HTTP_GET,
        Opcode.SYS_HTTP_POST,
        Opcode.AI_CALL,
        Opcode.AI_LEARN,
    ):
        assert op not in EXTERNAL_AI_BLOCKLIST


def test_consent_required_and_flags():
    """Valida CONSENT_REQUIRED (Sim* da Seção 7.1) e bitmasks da classe Flags (Seção 3.2)."""
    assert isinstance(CONSENT_REQUIRED, frozenset)
    assert CONSENT_REQUIRED == frozenset([
        Opcode.SYS_OPEN_APP,
        Opcode.SYS_NOTIFY,
        Opcode.SYS_HTTP_POST,
    ])
    combined = Flags.PRIVILEGED | Flags.ENCRYPTED | Flags.AUDITED | Flags.NO_CACHE | Flags.ASYNC
    assert combined == 0x1F