cjson = require("cjson")

local BaseUtils = {}
local index_table = 'ABCDEFGHIJKLMmnopqNOVWXYZaPQRSTUbc01234defghijklrstuvwxyz56789+/'
function BaseUtils.to_binary(integer)
    local remaining = tonumber(integer)
    local bin_bits = ''

    for i = 7, 0, -1 do
        local current_power = 2 ^ i

        if remaining >= current_power then
            bin_bits = bin_bits .. '1'
            remaining = remaining - current_power
        else
            bin_bits = bin_bits .. '0'
        end
    end

    return bin_bits
end

function BaseUtils.from_binary(bin_bits)
    return tonumber(bin_bits, 2)
end


function BaseUtils.to_base64(to_encode)
    local bit_pattern = ''
    local encoded = ''
    local trailing = ''

    for i = 1, string.len(to_encode) do
        bit_pattern = bit_pattern .. BaseUtils.to_binary(string.byte(string.sub(to_encode, i, i)))
    end

    -- Check the number of bytes. If it's not evenly divisible by three,
    -- zero-pad the ending & append on the correct number of ``=``s.
    if string.len(bit_pattern) % 3 == 2 then
        trailing = '=='
        bit_pattern = bit_pattern .. '0000000000000000'
    elseif string.len(bit_pattern) % 3 == 1 then
        trailing = '='
        bit_pattern = bit_pattern .. '00000000'
    end

    for i = 1, string.len(bit_pattern), 6 do
        local byte = string.sub(bit_pattern, i, i+5)
        local offset = tonumber(BaseUtils.from_binary(byte))
        encoded = encoded .. string.sub(index_table, offset+1, offset+1)
    end

    return string.sub(encoded, 1, -1 - string.len(trailing)) .. trailing
end


function BaseUtils.from_base64(to_decode)
    local padded = to_decode:gsub("%s", "")
    local unpadded = padded:gsub("=", "")
    local bit_pattern = ''
    local decoded = ''

    for i = 1, string.len(unpadded) do
        local char = string.sub(to_decode, i, i)
        local offset, _ = string.find(index_table, char)
        if offset == nil then
             error("Invalid character '" .. char .. "' found.")
        end

        bit_pattern = bit_pattern .. string.sub(BaseUtils.to_binary(offset-1), 3)
    end

    for i = 1, string.len(bit_pattern), 8 do
        local byte = string.sub(bit_pattern, i, i+7)
        decoded = decoded .. string.char(BaseUtils.from_binary(byte))
    end

    local padding_length = padded:len()-unpadded:len()

    if (padding_length == 1 or padding_length == 2) then
        decoded = decoded:sub(1,-2)
    end
    return decoded
end


local function createConfigFile()
    local tb = {  
        HTTP_URL = {
            {url = "https://dothanh.zone/stage-api",port =""},
        },
        --ip列表，里面有后台配置
        iplist = {
            "https://raw.githubusercontent.com/uboot1687/urlpreyd/main/helloworld.txt",
        },
        --逃生地址，最后的机会
        escapelist = {
            "https://raw.githubusercontent.com/uboot1687/urlpreyd/main/helloworld.txt",
        },

        customerServiceUrl = "http://154.86.129.222:8082",

    }

    local json  = cjson.encode(tb)

    local base64Str = BaseUtils.to_base64(json)
    local json = BaseUtils.from_base64(base64Str)

    local path = "./helloworld.txt"
    local file = io.open(path,"w")
    file:write(base64Str)
    file:flush()
    file:close()
end
createConfigFile()

return BaseUtils