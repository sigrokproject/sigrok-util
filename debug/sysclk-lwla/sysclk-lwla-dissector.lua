-- SysClk LWLA protocol dissector for Wireshark
--
-- Copyright (C) 2014 Daniel Elstner <daniel.kitta@gmail.com>
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

-- Usage: wireshark -X lua_script:sysclk-lwla-dissector.lua
--
-- It is not advisable to install this dissector globally, since
-- it will try to interpret the communication of any USB device
-- using the vendor-specific interface class.

-- Create custom protocol for the LWLA logic analyzer.
p_lwla = Proto("lwla", "LWLA USB Protocol")

-- LWLA message type.  For simplicity, the numerical value is the same
-- as the USB end point number the message is sent to or comes from.
local message_types = {
    [2] = "Control command",
    [4] = "Firmware transfer",
    [6] = "Control response"
}

-- Known IDs of LWLA control commands.
local control_commands = {
    [1] = "Read register",
    [2] = "Write register",
    [5] = "Write ???",
    [6] = "Read memory",
    [7] = "Capture setup",
    [8] = "Capture status"
}

-- Create the fields exhibited by the protocol.
p_lwla.fields.msgtype  = ProtoField.uint8("lwla.msgtype", "Message Type", base.DEC, message_types)
p_lwla.fields.command  = ProtoField.uint16("lwla.cmd", "Command ID", base.DEC, control_commands)
p_lwla.fields.memaddr  = ProtoField.uint32("lwla.memaddr", "Memory Address", base.HEX_DEC)
p_lwla.fields.memlen   = ProtoField.uint32("lwla.memlen", "Memory Read Length", base.HEX_DEC)
p_lwla.fields.regaddr  = ProtoField.uint16("lwla.regaddr", "Register Address", base.HEX)
p_lwla.fields.regdata  = ProtoField.uint32("lwla.regdata", "Register Value", base.HEX_DEC)
p_lwla.fields.stataddr = ProtoField.uint16("lwla.stataddr", "Status Memory Address", base.HEX)
p_lwla.fields.statlen  = ProtoField.uint16("lwla.statlen", "Status Memory Read/Write Length", base.HEX_DEC)
p_lwla.fields.statdata = ProtoField.bytes("lwla.statdata", "Status Word")
p_lwla.fields.stopdata = ProtoField.uint32("lwla.stopdata", "Stop Data", base.HEX_DEC)
p_lwla.fields.unknown  = ProtoField.bytes("lwla.unknown", "Unidentified message data")

-- Referenced USB URB dissector fields.
local f_urb_type = Field.new("usb.urb_type")
local f_transfer_type = Field.new("usb.transfer_type")
local f_endpoint = Field.new("usb.endpoint_number.endpoint")

-- Insert warning for undecoded leftover data.
local function warn_undecoded(tree, range)
    local item = tree:add(p_lwla.fields.unknown, range)
    item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
end

local function read_mixed_endian(range)
    return range(0,2):le_uint() * 65536 + range(2,2):le_uint()
end

local function read_stat_field(range)
    return string.char(range(5,1):uint(), range(4,1):uint(), range(7,1):uint(), range(6,1):uint(),
                       range(1,1):uint(), range(0,1):uint(), range(3,1):uint(), range(2,1):uint())
end

-- Dissect LWLA capture state.
local function dissect_capture_state(range, tree)
    for i = 0, range:len() - 8, 8 do
        tree:add(p_lwla.fields.statdata, range(i,8), read_stat_field(range(i,8)))
    end
end

-- Dissect LWLA control command messages.
local function dissect_command(range, pinfo, tree)
    if range:len() < 4 then
        return 0
    end

    tree:add_le(p_lwla.fields.command, range(0,2))
    local command = range(0,2):le_uint()

    if command == 1 then -- read register
        if range:len() == 4 then
            tree:add_le(p_lwla.fields.regaddr, range(2,2))
            pinfo.cols.info = string.format("Cmd %d: read reg 0x%04X",
                                            command, range(2,2):le_uint())
            return 4
        end
    elseif command == 2 then -- write register
        if range:len() == 8 then
            tree:add_le(p_lwla.fields.regaddr, range(2,2))
            local regval = read_mixed_endian(range(4,4))
            tree:add(p_lwla.fields.regdata, range(4,4), regval)
            pinfo.cols.info = string.format("Cmd %d: write reg 0x%04X value 0x%08X",
                                            command, range(2,2):le_uint(), regval)
            return 8
        end
    elseif command == 5 then -- write ???
        if range:len() == 66 then
            local infotext = string.format("Cmd %d: write ??? data", command)
            for i = 2, 62, 4 do
                local value = read_mixed_endian(range(i,4))
                tree:add(p_lwla.fields.stopdata, range(i,4), value)
                infotext = string.format("%s %02X", infotext, value)
            end
            pinfo.cols.info = infotext
            return 66
        end
    elseif command == 6 then -- read memory at address
        if range:len() == 10 then
            local memaddr = read_mixed_endian(range(2,4))
            local memlen  = read_mixed_endian(range(6,4))
            tree:add(p_lwla.fields.memaddr, range(2,4), memaddr)
            tree:add(p_lwla.fields.memlen,  range(6,4), memlen)
            pinfo.cols.info = string.format("Cmd %d: read mem 0x%06X length %d",
                                            command, memaddr, memlen)
            return 10
        end
    elseif command == 7 then -- capture setup
        if range:len() >= 6 then
            tree:add_le(p_lwla.fields.stataddr, range(2,2))
            tree:add_le(p_lwla.fields.statlen, range(4,2))
            local len = 8 * range(4,2):le_uint()
            if range:len() ~= len + 6 then
                warn_undecoded(tree, range(6))
                return 6
            end
            dissect_capture_state(range(6,len), tree)
            pinfo.cols.info = string.format("Cmd %d: setup 0x%X length %d",
                                            command, range(2,2):le_uint(), range(4,2):le_uint())
            return 6 + len
        end
    elseif command == 8 then -- capture status
        if range:len() == 6 then
            tree:add_le(p_lwla.fields.stataddr, range(2,2))
            tree:add_le(p_lwla.fields.statlen, range(4,2))
            pinfo.cols.info = string.format("Cmd %d: state 0x%X length %d",
                                            command, range(2,2):le_uint(), range(4,2):le_uint())
            return 6
        end
    end
    warn_undecoded(tree, range(2))
    return 2
end

-- Dissect LWLA control response messages.
local function dissect_response(range, pinfo, tree)
    -- The heuristics below are ugly and prone to fail, but they do the job
    -- for the purposes this dissector was written.
    if range:len() == 40 or range:len() == 80 then -- heuristic: response to command 8
        dissect_capture_state(range, tree)
        pinfo.cols.info = string.format("Ret 8: state length %d", range:len() / 8)
        return range:len()
    elseif range:len() == 4 then -- heuristic: response to command 1
        local value = read_mixed_endian(range(0,4))
        tree:add(p_lwla.fields.regdata, range(0,4), value)
        pinfo.cols.info = string.format("Ret 1: reg value 0x%08X", value)
        return 4
    elseif range:len() >= 18 and range:len() % 18 == 0 then -- heuristic: response to command 6
        pinfo.cols.info = string.format("Ret 6: mem data length %d", range:len() * 2 / 9)
        return 0
    else
        return 0
    end
end

-- Main LWLA dissector function.
function p_lwla.dissector(tvb, pinfo, tree)
    local transfer_type = tonumber(tostring(f_transfer_type()))

    -- Bulk transfers only.
    if transfer_type == 3 then
        local urb_type = tonumber(tostring(f_urb_type()))
        local endpoint = tonumber(tostring(f_endpoint()))

        -- Payload-carrying packets only.
        if (urb_type == 83 and (endpoint == 2 or endpoint == 4))
            or (urb_type == 67 and endpoint == 6)
        then
            pinfo.cols.protocol = p_lwla.name

            local subtree = tree:add(p_lwla, tvb(), "LWLA")
            subtree:add(p_lwla.fields.msgtype, endpoint):set_generated()

            -- Dispatch to message-specific dissection handler.
            if endpoint == 2 then
                return dissect_command(tvb, pinfo, subtree)
            elseif endpoint == 4 then
                pinfo.cols.info = "FPGA bitstream"
                return 0
            elseif endpoint == 6 then
                return dissect_response(tvb, pinfo, subtree)
            end
        end
    end
    return 0
end

-- Register LWLA protocol dissector during initialization.
function p_lwla.init()
--    local usb_product_dissectors = DissectorTable.get("usb.product")

    -- Dissection by vendor+product ID requires that Wireshark can get the
    -- the device descriptor.  Making a USB device available inside VirtualBox
    -- will make it inaccessible from Linux, so Wireshark cannot fetch the
    -- descriptor by itself.  However, it is sufficient if the VirtualBox
    -- guest requests the descriptor once while Wireshark is capturing.
--    usb_product_dissectors:add(0x29616689, p_lwla)

    -- Addendum: Protocol registration based on product ID does not always
    -- work as desired.  Register the protocol on the interface class instead.
    -- The downside is that it would be a bad idea to put this into the global
    -- configuration, so one has to make do with -X lua_script: for now.
    local usb_bulk_dissectors = DissectorTable.get("usb.bulk")

    -- For some reason the "unknown" class ID is sometimes 0xFF and sometimes
    -- 0xFFFF.  Register both to make it work all the time.
    usb_bulk_dissectors:add(0xFF, p_lwla)
    usb_bulk_dissectors:add(0xFFFF, p_lwla)
end
