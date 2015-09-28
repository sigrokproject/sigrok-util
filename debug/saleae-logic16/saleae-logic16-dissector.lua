-- Logic16 protocol dissector for Wireshark
--
-- Copyright (C) 2015 Stefan Bruens <stefan.bruens@rwth-aachen.de>
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

-- Usage: wireshark -X lua_script:saleae-logic16-dissector.lua
--
-- Create custom protocol for the Saleae Logic16 analyzer.
p_logic16 = Proto("Logic16", "Saleae Logic16 USB Protocol")

-- Known IDs of Logic16 control commands.
local control_commands = {
    [0x01] = "START_ACQUISITION",
    [0x02] = "ABORT_ACQUISITION_ASYNC",
    [0x06] = "WRITE_EEPROM",
    [0x07] = "READ_EEPROM",
    [0x7a] = "WRITE_LED_TABLE",
    [0x7b] = "SET_LED_MODE",
    [0x7c] = "RETURN_TO_BOOTLOADER",
    [0x7d] = "ABORT_ACQUISITION_SYNC",
    [0x7e] = "FPGA_UPLOAD_INIT",
    [0x7f] = "FPGA_UPLOAD_DATA",
    [0x80] = "FPGA_WRITE_REGISTER",
    [0x81] = "FPGA_READ_REGISTER",
    [0x82] = "GET_REVID"
}

-- Known Logic16 FPGA registers
local fpga_registers = {
    [0x00] = "Bitstream version",
    [0x01] = "Status and control",
    [0x02] = "Channel select low",
    [0x03] = "Channel select high",
    [0x04] = "Sample rate divisor",
    [0x05] = "LED brightness",
    [0x06] = "??? [0x06]",
    [0x07] = "??? [0x07]",
    [0x08] = "??? [0x08]",
    [0x09] = "??? [0x09]",
    [0x0a] = "Base clock",
    [0x0c] = "??? [0x0c]",
}

-- Create the fields exhibited by the protocol.
p_logic16.fields.command  = ProtoField.uint8("logic16.cmd", "Command ID", base.HEX_DEC, control_commands)
p_logic16.fields.regaddr  = ProtoField.uint8("logic16.regaddr", "Register Address", base.HEX, fpga_registers)
p_logic16.fields.regdata  = ProtoField.uint8("logic16.regdata", "Register Value", base.HEX_DEC)
p_logic16.fields.regcount = ProtoField.uint8("logic16.regcount", "Register Count", base.HEX_DEC)
p_logic16.fields.EE_len   = ProtoField.uint8("logic16.eeprom_len", "Read len", base.HEX_DEC)
p_logic16.fields.unknown  = ProtoField.bytes("logic16.unknown", "Unidentified message data")
p_logic16.fields.reg_addrs  = ProtoField.bytes("logic16.reg_addrs", "Register addresses")
p_logic16.fields.reg_av_pairs  = ProtoField.bytes("logic16.reg_av_pairs", "Register address/value pairs")

p_logic16.fields.rawdata   = ProtoField.bytes("logic16.rawdata", "Raw Message Data")
p_logic16.fields.decrypted = ProtoField.bytes("logic16.ep1_decrypted", "Decrypted message data")

-- Referenced USB URB dissector fields.
local f_urb_type = Field.new("usb.urb_type")
local f_transfer_type = Field.new("usb.transfer_type")
local f_endpoint = Field.new("usb.endpoint_number.endpoint")
local f_direction = Field.new("usb.endpoint_number.direction")

-- Decrypt EP1 message
local function decrypt_ep1_message(range)
   local iv = {0x9b, 0x54}
   local out = ByteArray.new()
   out:set_size(range:len())

   for i = 0, range:len() - 1, 1 do
      local s = range(i,1):uint()
      local dec = bit32.bxor(
                      (bit32.bxor((s +   0x45), 0x38) + 0xb0)
                    , 0x5a, iv[1])
            dec = bit32.bxor(
                      (bit32.bxor((dec + 0x39), 0x35) + 0x05)
                    , 0x2b, iv[2])
      local b = bit32.band(dec, 0xff)
      out:set_index(i, b)
      iv[1] = b
      iv[2] = s
   end

   return ByteArray.tvb(out, "Decrypted")
end

-- Dissect control command messages.
local function dissect_response(range, pinfo, tree)
    pinfo.cols.info = string.format("<- response: %s",
                                    tostring(range))
    local item = tree:add(p_logic16.fields.unknown, range())
    item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
    return range:len()
end

-- Dissect control command messages.
local function dissect_command(range, pinfo, tree)

    local command = range(0,1):uint()
    tree:add(p_logic16.fields.command, range(0,1))

    if command == 1 then -- start acquisition
        pinfo.cols.info = string.format("-> [%d]: START acquisition",
                                        command)
    elseif command == 2 then -- ABORT_ACQUISITION_ASYNC
        pinfo.cols.info = string.format("-> [%d]: ABORT acquisition",
                                        command)
    elseif command == 6 then -- WRITE_EEPROM
    elseif command == 7 then -- READ_EEPROM
        if range:len() == 5 then
            local regaddr = range(3,1):uint()
            local len     = range(4,1):uint()
            tree:add(p_logic16.fields.regaddr, range(3,1))
            tree:add(p_logic16.fields.EE_len,  range(4,1))
            pinfo.cols.info = string.format("-> [%d]: read EEPROM 0x%02X len=%d",
                                            command, regaddr, len)
            return 3
        end
    elseif command == 0x7a then -- WRITE_LED_TABLE
        local offset = range(1,1):uint()
        local len    = range(2,1):uint()
        pinfo.cols.info = string.format("-> [%d]: write LED table offset=%d len=%d",
                                        command, offset, len)

    elseif command == 0x7b then -- SET_LED_MODE
        pinfo.cols.info = string.format("-> [%d]: set LED mode flashing=%s",
                                        command, range(1,1):uint() and "on" or "off")

    elseif command == 0x7c then -- RETURN_TO_BOOTLOADER
    elseif command == 0x7d then -- ABORT_ACQUISITION_SYNC
        pinfo.cols.info = string.format("[%d]: ABORT acquisition SYNC",
                                        command)
    elseif command == 0x7e then -- FPGA_UPLOAD_INIT
    elseif command == 0x7f then -- FPGA_UPLOAD_DATA
    elseif command == 0x80 then -- FPGA_WRITE_REGISTER
        tree:add(p_logic16.fields.regcount, range(1,1))
        if range:len() == 4 then
            local regaddr = range(2,1):uint()
            local regval  = range(3,1):uint()
            tree:add(p_logic16.fields.regaddr,  range(2,1))
            tree:add(p_logic16.fields.regdata,  range(3,1))
            pinfo.cols.info = string.format("-> [%d]: FPGA write reg 0x%02X [%s] value 0x%02X",
                                            command, regaddr, fpga_registers[regaddr], regval)
            return 4
        else
            local n_regs = range(1,1):uint()
            pinfo.cols.info = string.format("-> [%d]: FPGA write reg (%d x)",
                                            command, n_regs)
            tree:add(p_logic16.fields.reg_av_pairs, range(2))
            return range:len()
        end

    elseif command == 0x81 then -- FPGA_READ_REGISTER
        tree:add(p_logic16.fields.regcount, range(1,1))
        if range:len() == 3 then
            local regaddr = range(2,1):uint()
            tree:add(p_logic16.fields.regaddr,  range(2,1))
            pinfo.cols.info = string.format("-> [%d]: FPGA read reg 0x%02X [%s]",
                                            command, regaddr, fpga_registers[regaddr])
            return 3
        else
            local n_regs = range(1,1):uint()
            pinfo.cols.info = string.format("-> [%d]: FPGA read reg (%d x)",
                                            command, n_regs)
            tree:add(p_logic16.fields.reg_addrs, range(2))
            return range:len()
        end

    elseif command == 0x82 then -- GET_REVID"
    end
    return range:len()
end

-- Main dissector function.
function p_logic16.dissector(tvb, pinfo, tree)
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
            pinfo.cols.protocol = p_logic16.name

            local subtree = tree:add(p_logic16, tvb(), "Logic16")
            subtree:add(p_logic16.fields.rawdata, tvb())

            local dec = decrypt_ep1_message(tvb)

            local dectree = subtree:add(p_logic16.fields.decrypted, dec())
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

-- Register Logic16 protocol dissector during initialization.
function p_logic16.init()
    local usb_product_dissectors = DissectorTable.get("usb.product")

    -- Dissection by vendor+product ID requires that Wireshark can get the
    -- the device descriptor.  Making a USB device available inside a VM
    -- will make it inaccessible from Linux, so Wireshark cannot fetch the
    -- descriptor by itself.  However, it is sufficient if the guest requests
    -- the descriptor once while Wireshark is capturing.
    usb_product_dissectors:add(0x21a91001, p_logic16)

    -- Addendum: Protocol registration based on product ID does not always
    -- work as desired.  Register the protocol on the interface class instead.
    -- The downside is that it would be a bad idea to put this into the global
    -- configuration, so one has to make do with -X lua_script: for now.
    -- local usb_bulk_dissectors = DissectorTable.get("usb.bulk")

    -- For some reason the "unknown" class ID is sometimes 0xFF and sometimes
    -- 0xFFFF.  Register both to make it work all the time.
    -- usb_bulk_dissectors:add(0xFF, p_logic16)
    -- usb_bulk_dissectors:add(0xFFFF, p_logic16)
end
