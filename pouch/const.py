# SPDX-License-Identifier: Apache-2.0
"""Protocol constants for Pouch (https://github.com/golioth/pouch)."""

# Pouch protocol version
POUCH_VERSION = 1

# Pouch GATT transport version
POUCH_GATT_VERSION = 1

# ---- Content types (CoAP Content-Formats) ----
CONTENT_TYPE_OCTET_STREAM = 42
CONTENT_TYPE_JSON = 50
CONTENT_TYPE_CBOR = 60

# ---- Block format constants ----
# Special block ID for entry (non-stream) blocks
BLOCK_ID_ENTRY = 0x00
# Mask for the stream-ID field in the block ID byte
BLOCK_ID_MASK = 0x1F
# Flag: first block in the stream
BLOCK_FLAG_FIRST = 0x40
# Flag: last block in the stream
BLOCK_FLAG_LAST = 0x80
# Size of the 3-byte block header (2 B size + 1 B id)
BLOCK_HEADER_SIZE = 3
# Maximum stream id value (stream IDs 1-126 are valid, 0 = entry block)
BLOCK_STREAM_ID_MAX = 126

# ---- Encryption types (used in Pouch header) ----
ENCRYPTION_NONE = 0
ENCRYPTION_SAEAD = 1

# ---- SAEAD encryption constants ----
# Algorithm identifiers (matches upstream session_info CDDL)
SAEAD_ALG_AES_GCM = 0
SAEAD_ALG_CHACHA20_POLY1305 = 1

# Role identifiers
POUCH_ROLE_DEVICE = 0
POUCH_ROLE_SERVER = 1

# Cryptographic lengths (bytes)
AUTH_TAG_LEN = 16
NONCE_LEN = 12
SESSION_ID_LEN = 16
CERT_REF_LEN = 6

# Maximum block payload size log (upstream default)
MAX_BLOCK_PAYLOAD_SIZE_LOG = 9  # 512 bytes

# ---- SAR (Segmentation and Reassembly) constants ----
SAR_TX_PKT_HEADER_LEN = 2
SAR_RX_PKT_LEN = 3
SAR_SEQ_MAX = 0xFF
SAR_SEQ_MASK = SAR_SEQ_MAX
SAR_WINDOW_MAX = 127
SAR_WINDOW_DEFAULT = 4

# SAR TX packet flags
SAR_FLAG_FIRST = 0x01
SAR_FLAG_LAST = 0x02
SAR_FLAG_FIN = 0x04
SAR_FLAG_IDLE = 0x08  # internal only – not part of the wire format

# SAR RX (ACK) packet codes
SAR_CODE_ACK = 0
SAR_CODE_NACK_UNKNOWN = 1
SAR_CODE_NACK_IDLE = 2

# ---- BLE GATT UUIDs ----
# 128-bit service UUID
GATT_SERVICE_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d272"
# Characteristics (device→gateway data; gateway ACKs on same char)
GATT_UPLINK_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d273"
# Characteristic (gateway→device data; device ACKs on same char)
GATT_DOWNLINK_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d274"
# Characteristic (device info; gateway ACKs on same char)
GATT_INFO_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d275"
# Characteristic (gateway→device server certificate)
GATT_SERVER_CERT_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d276"
# Characteristic (device→gateway device certificate)
GATT_DEVICE_CERT_UUID = "89a316ae-89b7-4ef6-b1d3-5c9a6e27d277"

# 16-bit UUID used in advertisement service data
GATT_ADV_UUID_16 = 0xFC49

# ---- BLE advertisement flags ----
GATT_ADV_FLAG_SYNC_REQUEST = 0x01
GATT_ADV_VERSION_POUCH_SHIFT = 4
GATT_ADV_VERSION_SELF_SHIFT = 0

# ---- BLE characteristic property flags ----
FLAG_READ = 0x0002
FLAG_WRITE_NO_RESPONSE = 0x0004
FLAG_WRITE = 0x0008
FLAG_NOTIFY = 0x0010
