-- RK Resumption Ticket Wireshark Dissector
-- OUI: 0x027a8b, Type: 0xff
-- Parses custom vendor IE ticket structure from vendor_ie_custom.c

local rk_vendor_proto = Proto("RKResumption", "RK Resumption Ticket")

-- Define protocol fields
local pf_oui_type = ProtoField.uint8("rk.oui_type", "OUI Type", base.HEX, {
    [0xff] = "Test/Development"
    -- Add more types here as needed:
    -- [0x01] = "Production Resumption Ticket",
    -- [0x02] = "Fast Roaming",
    -- etc.
})

-- Client identification fields (before ticket)
local pf_client_size = ProtoField.uint8("rk.client_size", "Client Size", base.DEC)
local pf_client_raw_encrypted = ProtoField.bytes("rk.client_raw_encrypted", "PMKD-Encrypted Client Raw")

-- Ticket envelope
local pf_ticket_size = ProtoField.uint8("rk.ticket_size", "Ticket Size", base.DEC)

-- RK-Encrypted Ticket fields (AES-GCM)
local pf_ticket_iv = ProtoField.bytes("rk.ticket_iv", "Ticket IV (AES-GCM Nonce)")
local pf_ticket_encrypted = ProtoField.bytes("rk.ticket_encrypted", "Encrypted Ticket Payload")
local pf_ticket_tag = ProtoField.bytes("rk.ticket_tag", "Ticket Auth Tag (AES-GCM)")

-- Ticket plaintext fields (after decryption, shown as encrypted)
local pf_client_hash_size = ProtoField.uint8("rk.client_hash_size", "Client Hash Size", base.DEC)
local pf_client_hash = ProtoField.bytes("rk.client_hash", "Client Hash (SHA256)")
local pf_pmk_size = ProtoField.uint8("rk.pmk_size", "PMK Size", base.DEC)
local pf_pmk = ProtoField.bytes("rk.pmk", "PMK")

-- 802.1X fields
local pf_auth_version = ProtoField.uint8("rk.auth_version", "802.1X Version", base.HEX, {
    [0x01] = "802.1X-2001",
    [0x02] = "802.1X-2004",
    [0x03] = "802.1X-2010"
})
local pf_auth_type = ProtoField.uint8("rk.auth_type", "802.1X Packet Type", base.HEX, {
    [0x00] = "EAP-Packet",
    [0x01] = "EAPOL-Start",
    [0x02] = "EAPOL-Logoff",
    [0x03] = "EAPOL-Key",
    [0x04] = "EAPOL-Encapsulated-ASF-Alert"
})
local pf_auth_msg_size = ProtoField.uint16("rk.auth_msg_size", "Auth Message Size", base.DEC)

-- EAPOL-Key fields
local pf_key_descriptor_type = ProtoField.uint8("rk.key_descriptor_type", "Key Descriptor Type", base.HEX, {
    [0x01] = "RC4 Cipher",
    [0x02] = "RSN Key",
    [0xFE] = "WPA Key"
})
local pf_key_information = ProtoField.uint16("rk.key_information", "Key Information", base.HEX)
local pf_key_length = ProtoField.uint16("rk.key_length", "Key Length", base.DEC)
local pf_replay_counter = ProtoField.bytes("rk.replay_counter", "Replay Counter")
local pf_key_nonce = ProtoField.bytes("rk.key_nonce", "Key Nonce")
local pf_key_iv = ProtoField.bytes("rk.key_iv", "Key IV")
local pf_key_rsc = ProtoField.bytes("rk.key_rsc", "Key RSC")
local pf_key_id = ProtoField.bytes("rk.key_id", "Key ID")
local pf_key_mic = ProtoField.bytes("rk.key_mic", "Key MIC")
local pf_key_data_length = ProtoField.uint16("rk.key_data_length", "Key Data Length", base.DEC)
local pf_key_data = ProtoField.bytes("rk.key_data", "Key Data")

-- Test data for non-debug builds
local pf_test_data = ProtoField.bytes("rk.test_data", "Test Data")

-- Register all fields
rk_vendor_proto.fields = {
    pf_oui_type,
    pf_client_size, pf_client_raw_encrypted,
    pf_ticket_size,
    pf_ticket_iv, pf_ticket_encrypted, pf_ticket_tag,
    pf_client_hash_size, pf_client_hash,
    pf_pmk_size, pf_pmk,
    pf_auth_version, pf_auth_type, pf_auth_msg_size,
    pf_key_descriptor_type, pf_key_information, pf_key_length,
    pf_replay_counter, pf_key_nonce, pf_key_iv,
    pf_key_rsc, pf_key_id, pf_key_mic,
    pf_key_data_length, pf_key_data,
    pf_test_data
}

-- Dissector function
function rk_vendor_proto.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()

    -- Check if we have at least OUI (3) + Type (1)
    if buf_len < 4 then
        return 0
    end

    -- Check OUI: 0x027a8b
    local oui = buffer(0, 3):uint()
    if oui ~= 0x027a8b then
        return 0
    end

    -- Check OUI Type (currently only 0xff supported)
    local oui_type = buffer(3, 1):uint()
    -- Future: Add support for other types here
    -- Supported types: 0xff (Test/Development)
    -- if oui_type ~= 0xff and oui_type ~= 0x01 and ... then
    --     return 0
    -- end
    if oui_type ~= 0xff then
        return 0  -- Only 0xff supported for now
    end

    pinfo.cols.protocol = "RK Resumption"

    -- Create main subtree
    local subtree = tree:add(rk_vendor_proto, buffer(), "RK Resumption Ticket")

    -- OUI (already checked, but display it)
    subtree:add(buffer(0, 3), "OUI: 0x027a8b")

    -- OUI Type
    subtree:add(pf_oui_type, buffer(3, 1))

    local offset = 4  -- Start after OUI + Type

    -- Dissect based on OUI Type
    -- Future: Add support for different payload structures per type
    if oui_type == 0xff then
        -- Type 0xff: Test/Development
        -- Check if this is minimal test data (non-CUSTOM_RK_NO_DEBUG build)
        -- Test data is just 2 bytes (0xaabb)
        if buf_len == 6 then  -- OUI (3) + Type (1) + Test Data (2)
            subtree:add(pf_test_data, buffer(offset, 2))
            pinfo.cols.info:append(" [Test/Development - Minimal]")
            return buf_len
        end

        -- Full ticket structure (CUSTOM_RK_NO_DEBUG build)
        pinfo.cols.info:append(" [Test/Development - Full Ticket]")
    end
    -- Future: Add other OUI Type handling here
    -- elseif oui_type == 0x01 then
    --     pinfo.cols.info:append(" [Production Resumption]")
    --     -- Handle different payload structure
    -- end

    -- Client Size (size of PMKD-Encrypted Client Raw)
    if offset >= buf_len then return buf_len end
    local client_size = buffer(offset, 1):uint()
    subtree:add(pf_client_size, buffer(offset, 1))
    offset = offset + 1

    -- PMKD-Encrypted Client Raw
    if offset >= buf_len then return buf_len end
    subtree:add(pf_client_raw_encrypted, buffer(offset, client_size))
    offset = offset + client_size

    -- Ticket Size (total size of RK-encrypted ticket: IV + Encrypted + Tag)
    if offset >= buf_len then return buf_len end
    local ticket_size = buffer(offset, 1):uint()
    subtree:add(pf_ticket_size, buffer(offset, 1))
    offset = offset + 1

    -- Create RK-Encrypted Ticket subtree
    local ticket_tree = subtree:add(rk_vendor_proto, buffer(offset, ticket_size), "RK-Encrypted Ticket (AES-256-GCM, " .. ticket_size .. " bytes)")

    -- Ticket IV / Nonce (12 bytes for AES-GCM)
    if offset + 12 > buf_len then return buf_len end
    ticket_tree:add(pf_ticket_iv, buffer(offset, 12))
    offset = offset + 12

    -- Encrypted Payload (ticket_size - 12 IV - 16 tag)
    local encrypted_payload_size = ticket_size - 12 - 16
    if encrypted_payload_size > 0 and offset + encrypted_payload_size <= buf_len then
        ticket_tree:add(pf_ticket_encrypted, buffer(offset, encrypted_payload_size)):append_text(" (" .. encrypted_payload_size .. " bytes)")
        offset = offset + encrypted_payload_size
    end

    -- Authentication Tag (16 bytes for AES-GCM)
    if offset + 16 <= buf_len then
        ticket_tree:add(pf_ticket_tag, buffer(offset, 16))
        offset = offset + 16
    end

    -- Note: The encrypted payload contains:
    -- - Client Hash Size (1 byte)
    -- - Client Hash (32 bytes)
    -- - PMK Size (1 byte)
    -- - PMK (32 bytes)
    -- - 802.1X Version (1 byte)
    -- - 802.1X Type (1 byte)
    -- - Auth Message Size (2 bytes)
    -- - EAPOL-Key frame (variable)
    -- These fields cannot be parsed without decryption
    -- ticket_tree:add(buffer(offset - encrypted_payload_size - 16, 0), "Note: Encrypted payload contains Client Hash, PMK, and EAPOL-Key frame")

    -- Skip remaining parsing since payload is encrypted
    -- The following code is commented out as it was for plaintext parsing
    --[[
    -- Client Hash Size
    if offset >= buf_len then return buf_len end
    local client_hash_size = buffer(offset, 1):uint()
    ticket_tree:add(pf_client_hash_size, buffer(offset, 1))
    offset = offset + 1

    -- EAPOL-Key frame
    local eapol_tree = ticket_tree:add(rk_vendor_proto, buffer(offset), "EAPOL-Key Frame")

    -- Key Descriptor Type
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_key_descriptor_type, buffer(offset, 1))
    offset = offset + 1

    -- Key Information (big-endian)
    if offset >= buf_len then return buf_len end
    local key_info = buffer(offset, 2):uint()
    local key_info_tree = eapol_tree:add(pf_key_information, buffer(offset, 2))

    -- Parse Key Information bits
    local key_desc_ver = bit.band(key_info, 0x0007)
    local key_type = bit.band(key_info, 0x0008)
    local key_index = bit.rshift(bit.band(key_info, 0x0030), 4)
    local install = bit.band(key_info, 0x0040)
    local key_ack = bit.band(key_info, 0x0080)
    local key_mic = bit.band(key_info, 0x0100)
    local secure = bit.band(key_info, 0x0200)
    local error = bit.band(key_info, 0x0400)
    local request = bit.band(key_info, 0x0800)
    local encrypted = bit.band(key_info, 0x1000)
    local smk = bit.band(key_info, 0x2000)

    key_info_tree:add(buffer(offset, 2), "Key Descriptor Version: " .. key_desc_ver)
    key_info_tree:add(buffer(offset, 2), "Key Type: " .. (key_type ~= 0 and "Pairwise" or "Group"))
    key_info_tree:add(buffer(offset, 2), "Key Index: " .. key_index)
    key_info_tree:add(buffer(offset, 2), "Install: " .. (install ~= 0 and "1" or "0"))
    key_info_tree:add(buffer(offset, 2), "Key ACK: " .. (key_ack ~= 0 and "1" or "0"))
    key_info_tree:add(buffer(offset, 2), "Key MIC: " .. (key_mic ~= 0 and "1" or "0"))
    key_info_tree:add(buffer(offset, 2), "Secure: " .. (secure ~= 0 and "1" or "0"))
    key_info_tree:add(buffer(offset, 2), "Error: " .. (error ~= 0 and "1" or "0"))
    key_info_tree:add(buffer(offset, 2), "Request: " .. (request ~= 0 and "1" or "0"))
    key_info_tree:add(buffer(offset, 2), "Encrypted Key Data: " .. (encrypted ~= 0 and "1" or "0"))
    key_info_tree:add(buffer(offset, 2), "SMK Message: " .. (smk ~= 0 and "1" or "0"))

    offset = offset + 2

    -- Key Length (big-endian)
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_key_length, buffer(offset, 2))
    offset = offset + 2

    -- Replay Counter (8 bytes)
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_replay_counter, buffer(offset, 8))
    offset = offset + 8

    -- Key Nonce (32 bytes)
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_key_nonce, buffer(offset, 32))
    offset = offset + 32

    -- Key IV (16 bytes)
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_key_iv, buffer(offset, 16))
    offset = offset + 16

    -- Key RSC (8 bytes)
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_key_rsc, buffer(offset, 8))
    offset = offset + 8

    -- Key ID (8 bytes)
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_key_id, buffer(offset, 8))
    offset = offset + 8

    -- Key MIC (16 bytes)
    if offset >= buf_len then return buf_len end
    eapol_tree:add(pf_key_mic, buffer(offset, 16))
    offset = offset + 16

    -- Key Data Length (big-endian)
    if offset >= buf_len then return buf_len end
    local key_data_len = buffer(offset, 2):uint()
    eapol_tree:add(pf_key_data_length, buffer(offset, 2))
    offset = offset + 2

    -- Key Data (if present)
    if key_data_len > 0 and offset + key_data_len <= buf_len then
        eapol_tree:add(pf_key_data, buffer(offset, key_data_len))
        offset = offset + key_data_len
    end
    --]]

    return buf_len
end

-- Register the dissector
function rk_vendor_proto.init()
    -- Method 1: Register for vendor specific IE tag (221 = 0xdd)
    local wlan_tag_table = DissectorTable.get("wlan.tag.number")
    if wlan_tag_table then
        wlan_tag_table:add(221, rk_vendor_proto)
    end

    -- Method 2: Try OUI-based registration as well
    local wlan_vendor_table = DissectorTable.get("wlan.tag.vendor.oui")
    if wlan_vendor_table then
        wlan_vendor_table:add(0x027a8b, rk_vendor_proto)
    end
end
