-- Logic Pro 16 protocol dissector for Wireshark
--
-- Copyright (C) 2016-2017 Jan Luebbe <jluebbe@lasnet.de>
--
-- based on the LWLA dissector, which is
--   Copyright (C) 2015 Stefan Bruens <stefan.bruens@rwth-aachen.de>
--
-- based on the LWLA dissector, which is
--   Copyright (C) 2014 Daniel Elstner <daniel.kitta@gmail.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, see <http://www.gnu.org/licenses/>.

-- Usage: wireshark -X lua_script:saleae-logicpro16-dissector.lua
--
-- Create custom protocol for the Saleae Logic Pro 16 analyzer.
p_logicpro16 = Proto("LogicPro16", "Saleae Logic Pro 16 USB Protocol")

local ctrl_enum = {
    [0x00] = "Normal",
    [0x20] = "Reseed",
}

local cmd_enum = {
    [0x01] = "Start Capture",
    [0x02] = "Stop Capture",
    [0x07] = "Read EEPROM",
    [0x7e] = "Prepare Firmware Upload",
    [0x7f] = "Upload Firmware",
    [0x80] = "Write Register",
    [0x81] = "Read Register",
    [0x87] = "Write I2C",
    [0x88] = "Read I2C",
    [0x89] = "Wake I2C",
    [0x8b] = "Read Firmware Version",
    [0x86] = "Read Temperature",
}

local reg_enum = {
    -- see https://www.hittite.com/content/documents/data_sheet/hmcad1100.pdf
    -- for ADC details
    [0x03] = "ADC Index",
    [0x04] = "ADC Value (LSB)",
    [0x05] = "ADC Value (MSB)",
    [0x08] = "Analog Channels (LSB)",
    [0x09] = "Analog Channels (MSB)",
    [0x06] = "Digital Channels (LSB)",
    [0x07] = "Digital Channels (MSB)",
    [0x0f] = "LED Red",
    [0x10] = "LED Green",
    [0x11] = "LED Blue",
    [0x12] = "Voltage",
    [0x15] = "Bank Power?",
    [0x17] = "Magic EEPROM Value?",
    [0x40] = "Capture Status",
}

local i2c_result_enum = {
    [0x01] = "Error",
    [0x02] = "OK",
}

local crypt_cmd_enum = {
    [0x00] = "Reset",
    [0x01] = "Sleep",
    [0x02] = "Idle",
    [0x03] = "Normal",
}

local crypt_op_enum = {
    [0x16] = "Nonce",
    [0x1b] = "Random",
    [0x41] = "Sign",
}

-- Create the fields exhibited by the protocol.
p_logicpro16.fields.req  = ProtoField.new("Request Frame", "logicpro16.req", ftypes.FRAMENUM)
p_logicpro16.fields.rsp  = ProtoField.new("Response Frame", "logicpro16.rsp", ftypes.FRAMENUM)

p_logicpro16.fields.ctrl  = ProtoField.uint8("logicpro16.ctrl", "Control Byte", base.HEX, ctrl_enum)
p_logicpro16.fields.cmd  = ProtoField.uint8("logicpro16.cmd", "Command Byte", base.HEX, cmd_enum)
p_logicpro16.fields.size  = ProtoField.uint16("logicpro16.size", "Payload Size")
p_logicpro16.fields.unknown  = ProtoField.bytes("logicpro16.unknown", "Unidentified message data")

p_logicpro16.fields.eepromaddr  = ProtoField.uint16("logicpro16.eepromaddr", "EEPROM Address", base.HEX_DEC)
p_logicpro16.fields.eepromsize  = ProtoField.uint16("logicpro16.eepromsize", "EEPROM Size", base.HEX_DEC)

p_logicpro16.fields.regaddr = ProtoField.uint8("logicpro16.regaddr", "Register Address", base.HEX_DEC, reg_enum)
p_logicpro16.fields.regval  = ProtoField.uint8("logicpro16.regval", "Register Value", base.HEX_DEC)

p_logicpro16.fields.i2caddr  = ProtoField.uint8("logicpro16.i2caddr", "I2C Address", base.HEX_DEC)
p_logicpro16.fields.i2csize  = ProtoField.uint16("logicpro16.i2csize", "I2C Size", base.HEX_DEC)
p_logicpro16.fields.i2cdata  = ProtoField.bytes("logicpro16.i2cdata", "I2C Data")
p_logicpro16.fields.i2cresult  = ProtoField.uint8("logicpro16.i2cresult", "I2C Result", base.HEX_DEC, i2c_result_enum)

p_logicpro16.fields.cryptcmd  = ProtoField.uint8("logicpro16.cryptcmd", "Crypt Command", base.HEX_DEC, crypt_cmd_enum)
p_logicpro16.fields.cryptcount  = ProtoField.uint8("logicpro16.cryptcount", "Crypt Count", base.HEX_DEC)
p_logicpro16.fields.cryptop  = ProtoField.uint8("logicpro16.cryptop", "Crypt Op", base.HEX_DEC, crypt_op_enum)
p_logicpro16.fields.cryptp1  = ProtoField.uint8("logicpro16.cryptp1", "Crypt Param 1", base.HEX_DEC)
p_logicpro16.fields.cryptp2  = ProtoField.uint16("logicpro16.cryptp2", "Crypt Param 2", base.HEX_DEC)
p_logicpro16.fields.cryptdata  = ProtoField.bytes("logicpro16.cryptdata", "Crypt Data")
p_logicpro16.fields.cryptcrc  = ProtoField.uint16("logicpro16.cryptcrc", "Crypt CRC", base.HEX_DEC)

p_logicpro16.fields.rawdata   = ProtoField.bytes("logicpro16.rawdata", "Raw Message Data")
p_logicpro16.fields.decrypted = ProtoField.bytes("logicpro16.decrypted", "Decrypted message data")

-- Referenced USB URB dissector fields.
local f_urb_type = Field.new("usb.urb_type")
local f_transfer_type = Field.new("usb.transfer_type")
local f_endpoint = Field.new("usb.endpoint_number.endpoint")
local f_direction = Field.new("usb.endpoint_number.direction")

local iv = 0x354B248E
local state = iv
local states = {}

local request_frame
local response_requests = {}
local request_responses = {}

local request_cmd
local response_cmds = {}

local crypt_op
local crypt_nonce_in
local crypt_nonce_out
local crypt_sign_out_crc

local function iterate_state()
    local max = bit32.band(state, 0x1f) + 34
    --print(string.format("shift -/%i state 0x%x", max, state))
    for i = 0, max, 1 do
        state = bit32.bor(
            bit32.rshift(state, 1),
            bit32.lshift(
                bit32.bxor(
                    state,
                    bit32.rshift(state, 1),
                    bit32.rshift(state, 21),
                    bit32.rshift(state, 31)
                ),
                31
            )
        )
        --print(string.format("shift %i/%i state 0x%x", i, max, state))
     end
end

local function reinit_state()
    print("in", crypt_nonce_in)
    print("out", crypt_nonce_out)
    print("crc", crypt_sign_out_crc)
    local input = crypt_nonce_in(4, 16) .. crypt_nonce_out(0, 28) .. crypt_sign_out_crc .. ByteArray.new("00000000") -- add padding
    print("input", input)
    local result = 0
    for i = 0, input:len()-4, 4 do
        result = bit32.bxor(
            result,
            input:get_index(i),
            bit32.lshift(input:get_index(i+1), 8),
            bit32.lshift(input:get_index(i+2), 16),
            bit32.lshift(input:get_index(i+3), 24)
        )
        print(string.format("iterate 0x%x 0x%x 0x%x 0x%x 0x%x", result, input:get_index(i), input:get_index(i+1), input:get_index(i+2), input:get_index(i+3)))
    end
    state = result
end

-- Decrypt EP1 OUT message
local function decrypt_ep1_out_message(pinfo, range)
    local out = ByteArray.new()
    out:set_size(range:len())
 
    local ctrl = range(0, 1):uint()
    local reseed = bit32.btest(ctrl, 0x20)
    if not pinfo.visited then
        if reseed then
            state = iv
        end
        states[pinfo.number] = state
    end
 
    local secret = states[pinfo.number]
    print("out visited", pinfo.visited, string.format("secret 0x%x", secret))
 
    for i = 0, range:len() - 1, 1 do
        local value = range(i,1):uint()
        local mask = bit32.extract(secret, 8*(i%4), 8)
        local dec
        if i == 0 then
            -- only 0x20 and 0x08 are relevant here
            dec = bit32.band(value, 0x28)
        else
            dec = bit32.bxor(value, mask)
        end
        out:set_index(i, dec)
    end
 
    tvb = ByteArray.tvb(out, "Decrypted")
 
    if not pinfo.visited then
        if reseed then
            state = tvb:range(1,4):le_uint()
            print("reseed", string.format("state 0x%x", secret))
        else
            iterate_state()
        end
    end
 
    return tvb
end

-- Decrypt EP1 IN message
local function decrypt_ep1_in_message(pinfo, range)
    local out = ByteArray.new()
    out:set_size(range:len())

    if not pinfo.visited then
       states[pinfo.number] = state
    end

    local secret = states[pinfo.number]
    print("in visited", pinfo.visited, string.format("secret 0x%x", secret))
 
    for i = 0, range:len() - 1, 1 do
        local value = range(i,1):uint()
        local mask = bit32.extract(secret, 8*(i%4), 8)
        local dec = bit32.bxor(value, mask)
        out:set_index(i, dec)
    end
 
    if not pinfo.visited then
        iterate_state()
    end
 
    return ByteArray.tvb(out, "Decrypted")
end

-- Dissect control command messages.
local function dissect_command(range, pinfo, tree)

    tree:add(p_logicpro16.fields.ctrl, range(0, 1))
    tree:add(p_logicpro16.fields.cmd, range(1, 1))
    local cmd = range(1, 1):uint()
    request_cmd = cmd
    request_frame = pinfo.number
    response_frame = request_responses[pinfo.number]

    pinfo.cols.info = string.format("command:  0x%02x %s",
                                    cmd, tostring(range))

    if not (response_frame == nil) then
        tree:add(p_logicpro16.fields.rsp, response_frame):set_generated()
    end

    if cmd == 0x7 then -- eeprom read
        tree:add(p_logicpro16.fields.unknown, range(2, 2))
        tree:add_le(p_logicpro16.fields.eepromaddr, range(4, 2))
        tree:add_le(p_logicpro16.fields.eepromsize, range(6, 2))
    elseif cmd == 0x7f then -- firmware upload
        tree:add_le(p_logicpro16.fields.size, range(2, 2))
        tree:add(p_logicpro16.fields.rawdata, range(4))
    elseif cmd == 0x80 then -- register write
        tree:add(p_logicpro16.fields.size, range(2, 1))
        local t = tree:add(p_logicpro16.fields.rawdata, range(3))
        for i = 0, range(2, 1):uint() - 1, 1 do
            t:add(p_logicpro16.fields.regaddr, range(3+i*2, 1))
            t:add(p_logicpro16.fields.regval, range(3+i*2+1, 1))
        end
    elseif cmd == 0x81 then -- register read
        tree:add(p_logicpro16.fields.size, range(2, 1))
        local t = tree:add(p_logicpro16.fields.rawdata, range(3))
        for i = 0, range(2, 1):uint() - 1, 1 do
            t:add(p_logicpro16.fields.regaddr, range(3+i, 1))
        end
    elseif cmd == 0x87 then -- i2c write
        tree:add(p_logicpro16.fields.i2caddr, range(2, 1))
        tree:add_le(p_logicpro16.fields.i2csize, range(3, 2))
        local t = tree:add(p_logicpro16.fields.i2cdata, range(5))
        t:add(p_logicpro16.fields.cryptcmd, range(5, 1))
        local cryptcmd = range(5, 1):uint()
        if cryptcmd == 0x03 then
            t:add(p_logicpro16.fields.cryptcount, range(6, 1))
            local cryptdatalen = range(6, 1):uint() - 7
            t:add(p_logicpro16.fields.cryptop, range(7, 1))
            crypt_op = range(7, 1):uint()
            t:add(p_logicpro16.fields.cryptp1, range(8, 1))
            t:add(p_logicpro16.fields.cryptp2, range(9, 2))
            if cryptdatalen > 0 then
                t:add(p_logicpro16.fields.cryptdata, range(11, cryptdatalen))
            end
            t:add(p_logicpro16.fields.cryptcrc, range(11+cryptdatalen, 2))
            if crypt_op == 0x16 then -- nonce
                crypt_nonce_in = range(11, cryptdatalen):bytes()
            end
        end
    elseif cmd == 0x88 then -- i2c read
        tree:add(p_logicpro16.fields.i2caddr, range(2, 1))
        tree:add_le(p_logicpro16.fields.i2csize, range(3, 2))
    elseif cmd == 0x89 then -- i2c wake
    else
        local item = tree:add(p_logicpro16.fields.unknown, range(2))
        item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
    end
    return range:len()
end

-- Dissect control response messages.
local function dissect_response(range, pinfo, tree)
    local cmd
    if not pinfo.visited then
        response_requests[pinfo.number] = request_frame
        response_cmds[pinfo.number] = request_cmd
        request_responses[request_frame] = pinfo.number
    else
        request_frame = response_requests[pinfo.number]
        request_cmd = response_cmds[pinfo.number]
    end

    print("visited", pinfo.visited, string.format("request_cmd 0x%x", request_cmd))
    pinfo.cols.info = string.format("response: 0x%02x %s",
                                    request_cmd, tostring(range))

    tree:add(p_logicpro16.fields.req, request_frame):set_generated()
    tree:add(p_logicpro16.fields.cmd, request_cmd):set_generated()

    if request_cmd == 0x81 then -- register read
        local t = tree:add(p_logicpro16.fields.rawdata, range(0))
    elseif request_cmd == 0x87 then -- i2c write
        tree:add(p_logicpro16.fields.i2cresult, range(0, 1))
        local t = tree:add(p_logicpro16.fields.i2cdata, range(1))
    elseif request_cmd == 0x88 then -- i2c read
        tree:add(p_logicpro16.fields.i2cresult, range(0, 1))
        local i2cresult = range(0, 1):uint()
        local t = tree:add(p_logicpro16.fields.i2cdata, range(1))
        if i2cresult == 0x02 then
            t:add(p_logicpro16.fields.cryptcount, range(1, 1))
            local cryptdatalen = range(1, 1):uint() - 3
            if cryptdatalen > 0 then
                t:add(p_logicpro16.fields.cryptdata, range(2, cryptdatalen))
            end
            t:add(p_logicpro16.fields.cryptcrc, range(2+cryptdatalen, 2))
            if crypt_op == 0x16 then -- nonce
                crypt_nonce_out = range(2, cryptdatalen):bytes()
            elseif crypt_op == 0x41 then -- sign
                crypt_sign_out_crc = range(2+cryptdatalen, 2):bytes()
                if not pinfo.visited then
                    reinit_state()
                end
            end
            crypt_op = nil
        end
    else
        local item = tree:add(p_logicpro16.fields.unknown, range())
        item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
    end
    return range:len()
end

-- Main dissector function.
function p_logicpro16.dissector(tvb, pinfo, tree)
    local transfer_type = tonumber(tostring(f_transfer_type()))

    -- Bulk transfers only.
    if transfer_type == 3 then
        local urb_type = tonumber(tostring(f_urb_type()))
        local endpoint = tonumber(tostring(f_endpoint()))
        local direction = tonumber(tostring(f_direction()))

        -- Payload-carrying packets only.
        if (urb_type == 83 and endpoint == 1)   -- 'S' - Submit
            or (urb_type == 67 and endpoint == 1) -- 'C' - Complete
        then
            pinfo.cols.protocol = p_logicpro16.name

            local subtree = tree:add(p_logicpro16, tvb(), "Logic Pro 16")
            subtree:add(p_logicpro16.fields.rawdata, tvb())

            local dec
            if (direction == 0) then
               dec = decrypt_ep1_out_message(pinfo, tvb)
            else
               dec = decrypt_ep1_in_message(pinfo, tvb)
            end

            local dectree = subtree:add(p_logicpro16.fields.decrypted, dec())
            dectree:set_generated()

            -- Dispatch to message-specific dissection handler.
            if (direction == 0) then
                return dissect_command(dec, pinfo, dectree)
            else
                return dissect_response(dec, pinfo, dectree)
            end
        end
    end
    return 0
end

-- Register Logic Pro 16 protocol dissector during initialization.
function p_logicpro16.init()
    local usb_product_dissectors = DissectorTable.get("usb.product")

    -- Dissection by vendor+product ID requires that Wireshark can get the
    -- the device descriptor.  Making a USB device available inside a VM
    -- will make it inaccessible from Linux, so Wireshark cannot fetch the
    -- descriptor by itself.  However, it is sufficient if the guest requests
    -- the descriptor once while Wireshark is capturing.
    usb_product_dissectors:add(0x21a91006, p_logicpro16)

    -- Addendum: Protocol registration based on product ID does not always
    -- work as desired.  Register the protocol on the interface class instead.
    -- The downside is that it would be a bad idea to put this into the global
    -- configuration, so one has to make do with -X lua_script: for now.
    -- local usb_bulk_dissectors = DissectorTable.get("usb.bulk")

    -- For some reason the "unknown" class ID is sometimes 0xFF and sometimes
    -- 0xFFFF.  Register both to make it work all the time.
    -- usb_bulk_dissectors:add(0xFF, p_logicpro16)
    -- usb_bulk_dissectors:add(0xFFFF, p_logicpro16)
end
