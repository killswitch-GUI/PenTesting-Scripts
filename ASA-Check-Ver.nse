-- The Head Section --
description = [[Cisco ASA Version Scan as an nmap NSE plugin.
Attempt to grab the Cisco ASA version from the Cisco ASA.]]

---
-- @usage
-- nmap --script ASA-Check.nse -p 443 <target>
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- |_cisco-asa-verscan: Version

author = "Killswitch-gui forked from alec-stuart"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    local uri = "/CSCOSSLC/config-auth"
    local options = {header={}}
    options['header']['User-Agent'] = "Cisco AnyConnect VPN Agent"
    local response = http.get(host, port, uri, options)
    output = {}


    if ( response.status == 200 ) then
    	local version = string.match(response.body, '.*<version who="sg">(.*)</version>')
        if (version ~= nil) then
	        verstr = string.gsub(version,"%D","")
            longver = tonumber(verstr)
	        while longver<10000 do
		        longver = longver *10
	        end
            
	        output[#output + 1] = "Cisco ASA version " .. version
            if(longver <83000 and longver < 82551) then
	            return "not checking"
            end
            return #output > 0 and stdnse.strjoin("\n", output) or nil
        else        
            return "Unknown"
        end
    end
end
