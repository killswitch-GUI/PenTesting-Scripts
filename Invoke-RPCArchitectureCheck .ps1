<#
    Invoke-RPCArchitectureCheck via .PS
    Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>

function Invoke-RPCArchitectureCheck {
<#
    .SYNOPSIS
        Invoke-RPCArchitectureCheck
        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
        Test Platforms: Windows 7
    .DESCRIPTION
        Invoke-RPCArchitectureCheck is a simple utility to use a crafted RPC packet to
        check a remote hosts arch. Returns is x86 or x64.
    .PARAMETER Target
        Host or target ip address.
    .EXAMPLE
        Invoke-RPCArchitectureCheck -Target 192.168.1.1
        Invoke-RPCArchitectureCheck -Target 192.168.1.1 -Verbose
        
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $Target
    )

    Begin {
        Write-Verbose "[*] Setting error action to stop"
        $ErrorActionPreference = "Stop"
        $outputVerbose = [bool]($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue)
    }
    
    
    Process {
        #Begin main process block exec of encryption
        Write-Verbose "[*] Attempting to con() to target" 
        $sock = rpc_dce_connect($Target)
        Write-Verbose "[*] Scoket Created!" 
        Write-Verbose "[*] Starting to build payload packet"
        $packet = make_rpc_packet($Target)
        Write-Verbose "[*] Packet built: "
        if ($outputVerbose) {
            Get-HexDump($packet)
        }
        Write-Verbose "[*] Sending packet to host!" 
        $sock.Send($packet) | Out-Null
        $tcp_response = [Array]::CreateInstance("byte", 100)
        try{
            $sock.Receive($tcp_response) | Out-Null
        }
        catch {
            Write-Warning "Socket error, failed to rec() from target"
        }
        Write-Verbose "[*] Packet from RPC server: "
        if ($outputVerbose) {
            Get-HexDump($tcp_response)
        }
        $resp = rpc_dce_bind_ack($tcp_response)
        Write-Verbose "[*] Packet stuc created: "
        if ($outputVerbose) {
            $resp
        }
        Write-Verbose "[*] Remote Target is: " 
        if ( $resp.item_1_ack_result[0] -ne 2 ) {
            $temp = @{
                        target = $Target;
                        architecture = "x86";
            }
            return $temp
        }
        if ( $resp.item_2_ack_result[0] -eq 0 ) {
            $temp = @{
                        target = $Target;
                        architecture = "x64";
            }
            return $temp
        }
        else {
            $temp = @{
                       target = $Target;
                       architecture = "unkown";
            }
            return $temp
        }
        
    }

    End {
        Write-Verbose "[*] Calling GC for packet clean up"
        [GC]::Collect()

    }
    

}



function rpc_dce_connect($target)
{
    $client = New-Object System.Net.Sockets.TcpClient($target,49152)
    $sock = $client.Client
    return $sock 

}

function rpc_dce_bind_ack($rpcack) {

    $parsed_header = @{
                        version = $rpcack[0];
                        version_minor = $rpcack[1];
                        packet_type = $rpcack[2];
                        packet_flags = $rpcack[3];
                        data_representation = $rpcack[4..7];
                        frag_length = $rpcack[8..9];
                        auth_length = $rpcack[10..11];
                        call_id = $rpcack[12..15];
                        max_xmit_frag = $rpcack[16..17];
                        max_recv_frag = $rpcack[18..19];
                        assoc_group = $rpcack[20..23];
                        scndry_addr_len = $rpcack[24..25];
                        scndry_addr = $rpcack[26..31];
                        num_results = $rpcack[32];
                        item_pad = $rpcack[33.35];
                        item_1_ack_result = $rpcack[36..37];
                        item_1_ack_reason = $rpcack[38..39];
                        item_1_transfer_syntax = $rpcack[40..55];
                        item_1_syntax_ver = $rpcack[56..59];
                        item_2_ack_result = $rpcack[60..61];
                        item_2_ack_reason = $rpcack[62..63];
                        item_2_transfer_syntax = $rpcack[64..79];
                        item_2_syntax_ver = $rpcack[80..83];
                     }
    return $parsed_header

}

function make_rpc_packet($Target) {

    ##################################
    # DEC/RPC Header Data (required) #
    ##################################
    [Byte[]] $pkt = [Byte[]] 0x05
    # Version 5.0 
    $pkt += 0x00
    # Packet needs to be a (Bind) call (int = 11)
    $pkt += 0x0B
    # Set packet flags (Binary = 00000011)
    $pkt += 0x03
    # set data network rep (order: Little Endian, Char: ASCII, Float: IEEE)
    # (Binary = 10000000)
    $pkt += 0x10,0x00,0x00,0x00
    # set frag length (int 116)
    $pkt += 0x74,0x00
    # Auth Length (No auth :)
    $pkt += 0x00,0x00
    # No call ID needed, we wont hit DCE UIDs
    $pkt += 0x00,0x00,0x00,0x00
    # Max Xmit Frag: (int 5840)
    $pkt += 0xD0,0x16
    # Max Recv Frag: (int 5840)
    $pkt += 0xD0,0x16
    # no asco group
    $pkt += 0x00,0x00,0x00,0x00
    # set the number of CTX items (2 for Arch check)
    $pkt += 0x02
    # padding 
    $pkt += 0x00,0x00,0x00

    Write-Verbose "[*] Built DCE-RPC Header"

    # TODO: add verbose print here with HEX+ASCII Dump

    ##################################
    #       DEC/RPC CTX Item 1       #
    ##################################
    # context ID
    $pkt += 0x00,0x00
    # num of trans items: (int 1)
    $pkt += 0x01,0x00
    # Abstract Syntax: MGMT V1.0
    # Interface: MGMT UUID: afa8bd80-7d8a-11c9-bef4-08002b102989
    $pkt += 0x80,0xBD,0xA8,0xAF,0x8A,0x7D,0xC9,0x11,0xBE,0xF4,0x08,0x00,0x2B,0x10,0x29,0x89
    # Interface Ver: 1
    $pkt += 0x01,0x00
    # Interface Ver Minor:
    $pkt += 0x00,0x00
    # Transfer Syntax[1]: 32bit NDR V2
    # Transfer Syntax: 32bit NDR UUID:8a885d04-1ceb-11c9-9fe8-08002b104860
    $pkt += 0x04,0x5D,0x88,0x8A,0xEB,0x1C,0xC9,0x11,0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60
    # Version (int 2)
    $pkt += 0x02,0x00,0x00,0x00

    Write-Verbose "[*] Built DCE-RPC CTX Item 1"

    # TODO: add verbose print here with HEX+ASCII Dump

    ##################################
    #       DEC/RPC CTX Item 2       #
    ##################################
    # context ID: 1
    $pkt += 0x01,0x00
    # num of trans items: (int 1)
    $pkt += 0x01,0x00
    # Abstract Syntax: MGMT V1.0
    # Interface: MGMT UUID: afa8bd80-7d8a-11c9-bef4-08002b102989
    $pkt += 0x80,0xBD,0xA8,0xAF,0x8A,0x7D,0xC9,0x11,0xBE,0xF4,0x08,0x00,0x2B,0x10,0x29,0x89
    # Interface Ver: 1
    $pkt += 0x01,0x00
    # Interface Ver Minor:
    $pkt += 0x00,0x00
    # Transfer Syntax[1]: 64bit NDR V1
    # Transfer Syntax: 64bit NDR UUID:71710533-beba-4937-8319-b5dbef9ccc36
    $pkt += 0x33,0x05,0x71,0x71,0xBA,0xBE,0x37,0x49,0x83,0x19,0xB5,0xDB,0xEF,0x9C,0xCC,0x36
    # Version (int 1)
    $pkt += 0x01,0x00,0x00,0x00

    # TODO: add verbose print here with HEX+ASCII Dump
    Write-Verbose "[*] Built DCE-RPC CTX Item 2"
    return $pkt

}

function Get-HexDump($bytes) 
{
    $chunks = [Math]::Ceiling($bytes.Length / 16);

    $hexDump = 0..($chunks – 1) | % {
        $bufferSize = if ($_ -ne $chunks – 1) { 16 } else { $bytes.Length – $_ * 16}
        [byte[]] $buffer = @(0) * $bufferSize
        [Array]::Copy($bytes, $_ * 16, $buffer, 0, $bufferSize)
        $bufferChars = [System.Text.Encoding]::ASCII.GetChars($buffer);
        $hexRow = ($_ * 16).ToString("X8") + ": "
        $hexRow += (($buffer | %{ $_.ToString("X2") }) -join " ")
        $hexRow += (" " * ((17 – $buffer.Length) * 3))
        $hexRow += (($bufferChars | %{ if ([char]::IsControl($_) -eq $true) { "." } else { "$_" } }) -join "")
        $hexRow
       
    }

    $hexDump
}
