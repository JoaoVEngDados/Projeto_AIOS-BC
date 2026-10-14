# core/opcodes.py
"""
Tabela de opcodes, flags, blocklists e codec binário de 8 bytes (64 bits, big-endian).
Baseado estritamente nas Seções 3.1, 3.2, 3.3, 5.2, 7.1, 13.3 e 13.4 da documentação v1.0.
"""
import struct


class Opcode:
    """Registro de opcodes AIOS-BC v1.0 (Seção 7.1)."""
    # Categoria: Controle e IA
    NOP = 0x00            # Sem operação / preenchimento (Externo: Sim)
    HALT = 0x01           # Para execução, libera caches (Externo: Não)
    INFER = 0x02          # Executa inferência GNN local (Externo: Não)

    # Categoria: KV Store
    KV_GET = 0x10         # Lê valor do cache KV cifrado (Externo: Sim)
    KV_SET = 0x11         # Grava valor no cache KV (Externo: Sim)
    KV_DEL = 0x12         # Remove chave do cache KV (Externo: Sim)

    # Categoria: IA (MHA + GNN + Softmax)
    MHA_HEAD = 0x20       # Executa cabeça de atenção (Externo: Não)
    GNN_LOOKUP = 0x21     # Busca nó no grafo de apps (Externo: Não)
    GNN_PROPAGATE = 0x22  # Propaga mensagem pelo grafo (Externo: Não)
    SOFTMAX = 0x23        # Normaliza scores, seleciona (Externo: Não)

    # Categoria: Sistema e Rede
    SYS_OPEN_APP = 0x30   # Abre app via deep-link (Externo: Sim*)
    SYS_NOTIFY = 0x31     # Emite notificação (Externo: Sim*)
    SYS_QUERY_CTX = 0x32  # Lê contexto do OS (Externo: Sim)
    SYS_HTTP_GET = 0x33   # GET em background (Externo: Sim)
    SYS_HTTP_POST = 0x34  # POST em background (Externo: Sim*)

    # Categoria: Adapter
    AI_CALL = 0x40        # Chama API de IA externa (Externo: Sim)
    AI_LEARN = 0x41       # Alimenta learner local (Externo: Sim)

    # Categoria: Segurança
    SEC_AUDIT = 0x50      # Emite entrada de auditoria (Externo: Não)
    SEC_REVOKE = 0x51     # Revoga permissão (Externo: NÃO)

    # Categoria: Reservados / Bloqueados (Seção 5.2, 7.1 e 13.4)
    RESERVED_F0 = 0xF0
    RESERVED_FE = 0xFE
    RESERVED_FF = 0xFF


class Flags:
    """Bits de controle de 8 bits (Seções 3.2, 3.3 e 13.4)."""
    PRIVILEGED = 0x01
    ENCRYPTED = 0x02
    AUDITED = 0x04
    NO_CACHE = 0x08
    ASYNC = 0x10


# Seção 5.2 e 7.1: Conjunto imutável (frozenset) de opcodes jamais executáveis por IA externa.
EXTERNAL_AI_BLOCKLIST = frozenset(
    list(range(0x60, 0x80))
    + list(range(0xF0, 0x100))
    + [
        Opcode.HALT,
        Opcode.INFER,
        Opcode.MHA_HEAD,
        Opcode.GNN_LOOKUP,
        Opcode.GNN_PROPAGATE,
        Opcode.SOFTMAX,
        Opcode.SEC_AUDIT,
        Opcode.SEC_REVOKE,
    ]
)

# Seção 5.2 e 7.1: Opcodes marcados com 'Sim*' que exigem aprovação explícita do usuário.
CONSENT_REQUIRED = frozenset([
    Opcode.SYS_OPEN_APP,
    Opcode.SYS_NOTIFY,
    Opcode.SYS_HTTP_POST,
])

# Seção 13.3: Instrução de 8 bytes: opcode(1) + flags(1) + key(4) + value(2)
_INSTR_STRUCT = struct.Struct('>BBIH')  # big-endian


def encode_instruction(opcode, flags, key, value=0) -> bytes:
    """Codifica instrução em 8 bytes big-endian (Seção 13.3)."""
    return _INSTR_STRUCT.pack(opcode, flags, key, value)


def decode_instruction(data: bytes) -> tuple:
    """Decodifica 8 bytes na tupla (opcode, flags, key, value) (Seção 13.3)."""
    if len(data) != 8:
        raise ValueError(f'Expected 8 bytes, got {len(data)}')
    return _INSTR_STRUCT.unpack(data)  # (opcode, flags, key, value)