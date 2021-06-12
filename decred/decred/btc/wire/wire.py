CmdVersion = "version"
CmdVerAck = "verack"
CmdGetAddr = "getaddr"
CmdAddr = "addr"
CmdGetBlocks = "getblocks"
CmdInv = "inv"
CmdGetData = "getdata"
CmdNotFound = "notfound"
CmdBlock = "block"
CmdTx = "tx"
CmdGetHeaders = "getheaders"
CmdHeaders = "headers"
CmdPing = "ping"
CmdPong = "pong"
CmdAlert = "alert"
CmdMemPool = "mempool"
CmdFilterAdd = "filteradd"
CmdFilterClear = "filterclear"
CmdFilterLoad = "filterload"
CmdMerkleBlock = "merkleblock"
CmdReject = "reject"
CmdSendHeaders = "sendheaders"
CmdFeeFilter = "feefilter"
CmdGetCFilters = "getcfilters"
CmdGetCFHeaders = "getcfheaders"
CmdGetCFCheckpt = "getcfcheckpt"
CmdCFilter = "cfilter"
CmdCFHeaders = "cfheaders"
CmdCFCheckpt = "cfcheckpt"
CmdSendAddrV2 = "sendaddrv2"

# MaxMessagePayload is the maximum bytes a message can be regardless of other
# individual limits imposed by messages themselves.
MaxMessagePayload = (1024 * 1024 * 32)  # 32MB

# MaxBlockPayload is the maximum bytes a block message can be in bytes.
# After Segregated Witness, the max block payload has been raised to 4MB.
MaxBlockPayload = 4000000


# ProtocolVersion is the latest protocol version this package supports.
ProtocolVersion = 70013

# MultipleAddressVersion is the protocol version which added multiple
# addresses per message (pver >= MultipleAddressVersion).
MultipleAddressVersion = 209

# NetAddressTimeVersion is the protocol version which added the
# timestamp field (pver >= NetAddressTimeVersion).
NetAddressTimeVersion = 31402

# BIP0031Version is the protocol version AFTER which a pong message
# and nonce field in ping were added (pver > BIP0031Version).
BIP0031Version = 60000

# BIP0035Version is the protocol version which added the mempool
# message (pver >= BIP0035Version).
BIP0035Version = 60002

# BIP0037Version is the protocol version which added new connection
# bloom filtering related messages and extended the version message
# with a relay flag (pver >= BIP0037Version).
BIP0037Version = 70001

# RejectVersion is the protocol version which added a new reject
# message.
RejectVersion = 70002

# BIP0111Version is the protocol version which added the SFNodeBloom
# service flag.
BIP0111Version = 70011

# SendHeadersVersion is the protocol version which added a new
# sendheaders message.
SendHeadersVersion = 70012

# FeeFilterVersion is the protocol version which added a new
# feefilter message.
FeeFilterVersion = 70013
