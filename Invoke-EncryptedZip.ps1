<#

    Invoke-MakeEncZip via .NET
    Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

#>


function Invoke-EncryptedZip {
<#
    .SYNOPSIS

        Invoke-EncryptedZip
        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Invoke-EncryptedZip is a utility to make a Enrypted Zip compresed file from a provided folder.
        This allows users to stage files in designated folder for exfil, or protection from final storage location. 

        Refrence: https://technet.microsoft.com/en-us/library/2009.04.heyscriptingguy.aspx

    .PARAMETER SourceDirectory

        Required source directory to be Zip Encrypted archived

    .PARAMETER ZipFileName

        Required Zip file name to be outputed

    .PARAMETER ZipFilePath

        Required Zip file output directory

    .PARAMETER EncryptedFileName

        Required final encrypted file name 

    .PARAMETER EncryptedFilePath

        Required final encrypted file path

    .PARAMETER ZipMethod

        Select the Method (COM, NET) to be used to Zip file (DEFAULT: NET)

    .PARAMETER EncryptMethod

        Select the Method (Stream, Memory) to be used to to encrypt the (DEFAULT: Stream)
        Memory is only good to about 1MB max to prevent PS consuming to much mem.

    .PARAMETER CleanUp

        Switch to enable clean up of source folder and zip file created. (DEFAULT: False)

    .EXAMPLE

        Invoke-EncryptedZip -SourceDirectory "C:\CINEBENCHR15.038" -ZipFileName "test.zip" -ZipFilePath "C:\" -EncryptedFilePath "C:\"
        
        Invoke-EncryptedZip -SourceDirectory "C:\CINEBENCHR15.038" -ZipFileName "test.zip" -ZipFilePath "C:\\" -EncryptedFilePath "C:\" -ZipMethod  'COM' 

        Invoke-EncryptedZip -SourceDirectory "C:\CINEBENCHR15.038" -ZipFileName "test.zip" -ZipFilePath "C:\\" -EncryptedFilePath "C:\" -ZipMethod  'COM' -EncryptMethod 'Memory'

        Invoke-EncryptedZip -SourceDirectory "C:\CINEBENCHR15.038" -ZipFileName "test.zip" -ZipFilePath "C:\\" -EncryptedFilePath "C:\" -ZipMethod  'NET' -EncryptMethod 'Stream' -ZipMethod 'NET' -EncryptMethod 'Stream' -CleanUp -Verbose

        
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $SourceDirectory,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $ZipFileName,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $ZipFilePath,

        [Parameter(Mandatory = $true, Position = 3)]
        [string]
        $EncryptedFileName,

        [Parameter(Mandatory = $true, Position = 4)]
        [string]
        $EncryptedFilePath,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet("COM", "NET")]
        [String]
        $ZipMethod = "NET",

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet("Stream", "Memory")]
        [String]
        $EncryptMethod = "Stream",

        [Parameter(Mandatory = $false, Position = 7)]
        [Switch]
        $CleanUp = $false
    )

    Begin {
        $ErrorActionPreference = "Stop"
        if(![IO.Directory]::Exists($SourceDirectory)){
                Write-Error "[!] Cant find source directory $SourceDirectory, baling out"
                Exit
        }
        # Create zip file and test to make sure it was wrote to correct location
        if ($ZipMethod -eq "COM") {
            Create-ZipFileCOM -SourceDirectory $SourceDirectory -ZipFileName $ZipFileName -ZipFilePath $ZipFilePath
        }
        if ($ZipMethod -eq "NET") {
            Create-ZipFileNET -SourceDirectory $SourceDirectory -ZipFileName $ZipFileName -ZipFilePath $ZipFilePath
        } 
        $ZipFile = "$ZipFilePath$ZipFileName"
        if(-not (test-path($ZipFile))) {
            Write-Output "[!] No zip present after creation, baling out!"
            Exit
        }
        sleep 2
    }
    
    
    Process {
        #Begin main process block exec of encryption 
        if ($EncryptMethod -eq "Stream") {
            Write-Verbose "[*] Stream encryption selected"
            $AesKey = Create-AesKey
            $Result = Encrypt-AESFileStream -SourceDirectory $ZipFilePath -SourceFile $ZipFileName -EncryptedFileName $EncryptedFileName -EncryptedFilePath $EncryptedFilePath -AesKey $AesKey
            remove-variable AesKey
            [GC]::Collect()

        }
        if ($EncryptMethod -eq "Memory") {
            Write-Verbose "[*] Memory encryption selected"
            $FileBytes = [System.IO.File]::ReadAllBytes($ZipFile)
            $AesKey = Create-AesKey
            $EncryptedBytes = Encrypt-Bytes -AesKey $AesKey -Bytes $FileBytes
            remove-variable FileBytes
            [GC]::Collect()
            $EncryptedFile = "$EncryptedFilePath$EncryptedFileName"
            [io.file]::WriteAllBytes($EncryptedFile, $EncryptedBytes)
            remove-variable EncryptedBytes
            [GC]::Collect()
            $Result = New-Object –TypeName PSObject
            $Result | Add-Member –MemberType NoteProperty –Name Computer –Value $env:COMPUTERNAME
            $Result | Add-Member –MemberType NoteProperty –Name Key –Value $AesKey
            $Result | Add-Member –MemberType NoteProperty –Name Files –Value $EncryptedFile
        }
    }

    End {
        [GC]::Collect()
        if ($CleanUp) {
            # start file clean up routine 
            Remove-Item $SourceDirectory -Recurse -Force
            Write-Verbose "[*] Source folder deleted: $SourceDirectory"
            Remove-Item $ZipFile -Force
            Write-Verbose "[*] Zip archive deleted: $ZipFile"
            if([IO.Directory]::Exists($SourceDirectory)){
                Write-Warning "[!] WARNING: Source folder deletion failed, please manualy remove: $SourceDirectory"
            }
            if([System.IO.File]::Exists($ZipFileName)){
                Write-Warning "[!] WARNING: Zip deletion failed, please manualy remove: $ZipFile"
            }
        }
        return $Result
    }
    

}


function Invoke-DecryptZip {
<#
    .SYNOPSIS

        Invoke-EncryptedZip
        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Invoke-DecryptZip is a utility to decrypt files created with this utility.

        Refrence: https://technet.microsoft.com/en-us/library/2009.04.heyscriptingguy.aspx

    .PARAMETER EncryptedFileName

        Required final encrypted file name 

    .PARAMETER EncryptedFilePath

        Required final encrypted file path

    .PARAMETER ZipMethod

        Select the Method (COM, NET) to be used to Zip file (DEFAULT: NET)

    .PARAMETER EncryptMethod

        Select the Method (Stream, Memory) to be used to to encrypt the (DEFAULT: Stream)
        Memory is only good to about 1MB max to prevent PS consuming to much mem.

    .PARAMETER CleanUp

        Switch to enable clean up of source folder and zip file created. (DEFAULT: False)

    .EXAMPLE
        
        Invoke-DecryptZip -EncryptedFileName 'shellcode.dat' -EncryptedFilePath 'C:\Users\admin\Desktop\' -AesKey  'H2dbIaoK2MFYU2ge/4cx00XjLuLSC63odhqhKP4vC84=' 

        Invoke-DecryptZip -EncryptedFileName 'shellcode.dat' -EncryptedFilePath 'C:\Users\admin\Desktop\' -AesKey  'H2dbIaoK2MFYU2ge/4cx00XjLuLSC63odhqhKP4vC84=' -CleanUp -Verbose

        Computer     Key                                          Files
        --------     ---                                          -----
        TEST         H2dbIaoK2MFYU2ge/4cx00XjLuLSC63odhqhKP4vC84= C:\Users\admin\Desktop\shellcode.zip
        
#>

    [CmdletBinding()]
    Param (

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $AesKey,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $EncryptedFileName,

        [Parameter(Mandatory = $true, Position = 3)]
        [string]
        $EncryptedFilePath,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet("COM", "NET")]
        [String]
        $ZipMethod = "NET",

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet("Stream", "Memory")]
        [String]
        $EncryptMethod = "Stream",

        [Parameter(Mandatory = $false, Position = 6)]
        [Switch]
        $CleanUp = $false
    )

    Begin {
        $ErrorActionPreference = "Stop"
        $EncryptedFile = "$EncryptedFilePath$EncryptedFileName"
        $DecryptedFile = $EncryptedFileName.Split(".")[0] + ".zip"
        if(![System.IO.File]::Exists($EncryptedFile)){
                Write-Error "[!] Cant find Encrypted File $EncryptedFile, baling out"
        }
        if ($EncryptMethod -eq "Stream") {
            Write-Verbose "[*] Stream dcryption selected"
            $Result = Decrypt-AESFileStream -DestionationDirectory $EncryptedFilePath -DestionationFile $DecryptedFile -EncryptedFileName $EncryptedFileName -EncryptedFilePath $EncryptedFilePath -AesKey $AesKey
            remove-variable AesKey
            [GC]::Collect()

        }
    }
    
    
    Process {
        #Begin main process block exec of de ziping 
        $ZipFile = "$EncryptedFilePath$DecryptedFile"
        $DecryptedFolder = $EncryptedFileName.Split(".")[0]
        $DecompressedZipFolder = "$EncryptedFilePath$DecryptedFolder"
        if ($ZipMethod -eq "NET") {
            Create-DecompressedZipFileNET -ZipFilePath $ZipFile -OutputFolderPath $DecompressedZipFolder
        } 
        Write-Verbose "[*] Zip decompressed to: $DecompressedZipFolder"
        if(![IO.Directory]::Exists($DecompressedZipFolder)){
                Write-Error "[!] No folder Decompressed present after creation, baling out!"
        }
    }

    End {
        [GC]::Collect()
        if ($CleanUp) {
            # start file clean up routine 
            Remove-Item $EncryptedFile -Force
            Write-Verbose "[*] Source file deleted: $EncryptedFile"
            Remove-Item $ZipFile -Force
            Write-Verbose "[*] Zip archive deleted: $ZipFile"
            if([IO.Directory]::Exists($EncryptedFile)){
                Write-Warning "[!] WARNING: Source folder deletion failed, please manualy remove: $EncryptedFile"
            }
            if([System.IO.File]::Exists($ZipFile)){
                Write-Warning "[!] WARNING: Zip deletion failed, please manualy remove: $ZipFile"
            }
        }
        return $Result
    }
    

}

function Create-AesManagedObject {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Makes the required AES object for encryption and decryption 

        Refrence: https://gist.github.com/ctigeek/2a56648b923d198a6e60

    .PARAMETER AesKey

        The required AES key being used for encryption (base64 key)

    .PARAMETER AesIV

        The required AES IV being used for encryption (base64 iv)


    .EXAMPLE

        Create-AesManagedObject $key $iv
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [String]
        $AesKey,

        [Parameter(Mandatory = $false, Position = 1)]
        [string]
        $AesIV
    )

    Begin {
        if ($AesKey) {
            Write-Verbose "[*] Key being used for encryption: $AesKey"
        }
        if ($AesIV) {
            Write-Verbose "[*] IV being used for encryption: $iv"
        }
    }
   
    Process {
            #Begin main process block
            $ErrorActionPreference = "Stop"
            $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
            $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $aesManaged.BlockSize = 128
            $aesManaged.KeySize = 256
            if ($AesIV) {
                if ($AesIV.getType().Name -eq "String") {
                    $aesManaged.IV = [System.Convert]::FromBase64String($AesIV)
                }
                else {
                    $aesManaged.IV = $AesIV
                }
            }
            if ($AesKey) {
                if ($AesKey.getType().Name -eq "String") {
                    $aesManaged.Key = [System.Convert]::FromBase64String($AesKey)
                }
                else {
                    $aesManaged.Key = $AesKey
                }
            }
    }

    End {

        Write-Verbose "[*] Completed AES object creation"
        # return obj to pipeline
        $aesManaged
    }
    

}

function Create-AesKey {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Makes the required AES key object to pass

        Refrence: https://gist.github.com/ctigeek/2a56648b923d198a6e60


    .EXAMPLE

        $b64key = Create-AesKey 
#>

    Begin {
        Write-Verbose "[*] AES key creation started"
        }
    
    
        Process {
    
            #Begin main process block
            $ErrorActionPreference = "Stop"
            $aesManaged = Create-AesManagedObject
            $aesManaged.GenerateKey()
    }

    End {

        Write-Verbose "[*] Completed AES key creation"
        # return obj to pipeline
        $AesKey = [System.Convert]::ToBase64String($aesManaged.Key)
        Write-Verbose "[*] AES key created: $AesKey"
        return $AesKey
    }
    
}


function Encrypt-Bytes {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Makes the required AES object for encryption and decryption 

        Refrence: https://gist.github.com/ctigeek/2a56648b923d198a6e60

    .PARAMETER AesKey

        The required AES key being used for encryption (base64 key)

    .PARAMETER Bytes

        The bytes to be encrypted via AES


    .EXAMPLE

        Encrypt-Bytes $AesKey $FileBytes
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $AesKey,

        [Parameter(Mandatory = $true, Position = 1)]
        $Bytes
    )

    Begin {
        Write-Verbose "[*] Key being used for encryption of bytes: $key"
        }
    
    
        Process {
        $ErrorActionPreference = "Stop"
        $aesManaged = Create-AesManagedObject $AesKey
        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length);
        [byte[]] $fullData = $aesManaged.IV + $encryptedData
        $aesManaged.Dispose()
        # $finalbytes = [System.Convert]::ToBase64String($fullData)
        $finalbytes = $fullData

    }

    End {

        Write-Verbose "[*] Completed AES encryption of bytes"
        # return obj to pipeline
        $finalbytes
    }
    

}

function Create-ZipFileCOM {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Makes the required AES object for encryption and decryption 

        Refrence: https://serverfault.com/questions/456095/zipping-only-files-using-powershell

    .PARAMETER SourceDirectory

        Required source directory to be Zip archived

    .PARAMETER ZipFileName

        Required Zip file name to be outputed

    .PARAMETER ZipFilePath

        Required Zip file output directory

    .EXAMPLE

        Create-ZipFile -SourceDirectory "C:\Users\KILLSWITCH-GUI\Desktop\Ethereum-Wallet-win32-0-8-10\win-ia32-unpacked" -ZipFileName "test.zip" -ZipFilePath "C:\Users\KILLSWITCH-GUI\Desktop\" -Verbose
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $SourceDirectory,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $ZipFileName,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $ZipFilePath
    )

    Begin {
        $ErrorActionPreference = "Stop"
        $zipFile = "$ZipFilePath$ZipFileName"
        Write-Verbose "[*] Full Zip file output path: $zipFile"
        Write-Verbose "[*] Full path of folder to be zipped: $SourceDirectory"
        #Prepare zip file on disk
        if(-not (test-path($zipFile))) {
            set-content $zipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
            (dir $zipFile).IsReadOnly = $false  
        }
    }
    
    Process {
        $shellApplication = new-object -com shell.application
        $zipPackage = $shellApplication.NameSpace($zipFile)
        $files = Get-ChildItem -Path $SourceDirectory 

        foreach($file in $files) { 
            $zipPackage.CopyHere($file.FullName)
            while($zipPackage.Items().Item($file.name) -eq $null){
            Write-Verbose "[*] Completed compression on file: $file"
                Start-sleep -seconds 1
            }
        }

    }

    End {
        $len = (Get-Item "$zipFile").length
        # TODO: Fix addtype
        # $size = Convert-Size -Size $len
        $size = $len
        Write-Verbose "[*] Completed Zip file creation"
        Write-Verbose "[*] Final Zip file size: $size"
    }
    

}


function Create-DecompressedZipFileNET {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Uses .NET to Decompressed zip file to directory

        Refrence: https://stackoverflow.com/questions/1153126/how-to-create-a-zip-archive-with-powershell

    .PARAMETER ZipFilePath

        Required Zip file full file path Ex: C:\Windows\Tasks\test.zip

    .PARAMETER OutputFolderPath

        Required output directory that will be created Ex: C:\Windows\Tasks\test
        This creates a directory. As .NET can only zip a directory.
      
    .EXAMPLE

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $ZipFilePath,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $OutputFolderPath
    )

    Begin {
        $ErrorActionPreference = "Stop"
        Write-Verbose "[*] Full path of file to be Decompressed: $ZipFilePath"
        Write-Verbose "[*] Full path of zip file to be stored to: $OutputFolderPath"
    }
    
    Process {
        [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") > $null
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipFilePath,$OutputFolderPath)
    }

    End {
        Write-Verbose "[*] Completed Decompressed file creation"
    }
    

}

function Create-ZipFileNET {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Uses .NET to zip file directory

        Refrence: https://stackoverflow.com/questions/1153126/how-to-create-a-zip-archive-with-powershell

    .PARAMETER SourceDirectory

        Required source directory to be Zip archived

    .PARAMETER ZipFileName

        Required Zip file name to be outputed

    .PARAMETER ZipFilePath

        Required Zip file output directory

    .EXAMPLE

        Create-ZipFile -SourceDirectory "C:\Users\KILLSWITCH-GUI\Desktop\Ethereum-Wallet-win32-0-8-10\win-ia32-unpacked" -ZipFileName "test.zip" -ZipFilePath "C:\Users\KILLSWITCH-GUI\Desktop\" -Verbose
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $SourceDirectory,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $ZipFileName,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $ZipFilePath
    )

    Begin {
        $ErrorActionPreference = "Stop"
        $zipFile = "$ZipFilePath$ZipFileName"
        Write-Verbose "[*] Full Zip file output path: $zipFile"
        Write-Verbose "[*] Full path of folder to be zipped: $SourceDirectory"
    }
    
    Process {
        [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") > $null
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
        [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceDirectory,
            $zipFile, $compressionLevel, $false)
    }

    End {
        $len = (Get-Item "$zipFile").length
        # TODO: Fix addtype
        # $size = Convert-Size -Size $len
        $size = $len
        Write-Verbose "[*] Completed Zip file creation"
        Write-Verbose "[*] Final Zip file size: $size"
    }
    

}

function Encrypt-AESFileStream {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Uses .NET to encrypt using file stream rather than fully in mem.

        Refrence: https://stackoverflow.com/questions/1153126/how-to-create-a-zip-archive-with-powershell
                  https://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptostream.cryptostream(v=vs.110).aspx
                  https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d


    .PARAMETER SourceDirectory

        Required source directory of file directory to be encrypted
    
    .PARAMETER SourceFile

        Required source file name to be encrypted

    .PARAMETER EncryptedFileName

        Required final encrypted file name 

    .PARAMETER EncryptedFilePath

        Required final encrypted file path

    .PARAMETER AesKey

        Required AES key to be used for encryption
    
    .NOTES
        
        Adapted from Tyler Siegrist.

    .EXAMPLE

        $key = Create-AesKey

        Encrypt-AESFileStream -SourceDirectory "C:\Users\admin\Desktop\" -SourceFile "secrets.txt" -EncryptedFileName "secrets.crypto" -EncryptedFilePath "C:\Users\admin\Desktop\" -AesKey $key

        Computer     Key                                          Files
        --------     ---                                          -----
        TEST         7f/3e9cQF8yx2UNhG/Dc6XYLKYqXptK1ALB+tP3QUwA= C:\Users\admin\Desktop\secrets.crypto
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $SourceDirectory,

        [Parameter(Mandatory = $true, Position = 1)]
        [String]
        $SourceFile,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $EncryptedFileName,

        [Parameter(Mandatory = $true, Position = 3)]
        [string]
        $EncryptedFilePath,

        [Parameter(Mandatory = $true, Position = 4)]
        [string]
        $AesKey
    )

    Begin {
        $ErrorActionPreference = "Stop"
        $EncryptedFile = "$EncryptedFilePath$EncryptedFileName"
        $SourceFileName = "$SourceDirectory$SourceFile"
        $AESProvider = Create-AesManagedObject -AesKey $AesKey
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
        if(![System.IO.File]::Exists($SourceFileName)){
            Write-Verbose "[*] File check failed: $SourceFileName"
            Write-Error "[!] File not present? Check your self!"
        }
        Write-Verbose "[*] File check passed: $SourceFileName"
    }
    
    Process {
        # create the file stream for the encryptor
        $FileStreamReader = New-Object System.IO.FileStream($SourceFileName, [System.IO.FileMode]::Open)
       
   
        # create destination file
        Try
        {
            $FileStreamWriter = New-Object System.IO.FileStream($EncryptedFile, [System.IO.FileMode]::Create)
        }
        Catch
        {
            Write-Error "[!] Unable to open file to write: $FileStreamWriter"
            $FileStreamReader.Close()
            $FileStreamWriter.Close()
        }
        # write IV length & IV to encrypted file header
        $AESProvider.GenerateIV()
        $FileStreamWriter.Write([System.BitConverter]::GetBytes($AESProvider.IV.Length), 0, 4)
        $FileStreamWriter.Write($AESProvider.IV, 0, $AESProvider.IV.Length)
        # start encryption routine 
        Write-Verbose "[*] Encrypting $SourceFileName with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

        try
        {
            $Transform = $AESProvider.CreateEncryptor()
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            [Int]$Count = 0
            [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
            [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
            Do
            {
                $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                $CryptoStream.Write($Data, 0, $Count)
            }
            While($Count -gt 0)
    
            #Close open files
            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamReader.Close()
            $FileStreamWriter.Close()
            # finshed
            Write-Verbose "[*] Successfully encrypted file: $EncryptedFile"
        }
        catch
        {
            Write-Error "[!] Failed to encrypt: $SourceFileName"
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()
            Remove-Item $EncryptedFile -Force
        }
    }

    End {
        $len = (Get-Item "$EncryptedFile").length
        # TODO: Fix addtype
        # $size = Convert-Size -Size $len
        $size = $len
        Write-Verbose "[*] Final encrypted file size: $size"
        $Result = New-Object –TypeName PSObject
        $Result | Add-Member –MemberType NoteProperty –Name Computer –Value $env:COMPUTERNAME
        $Result | Add-Member –MemberType NoteProperty –Name Key –Value $AesKey
        $Result | Add-Member –MemberType NoteProperty –Name Files –Value $EncryptedFile
        return $Result
    }
    

}

function Decrypt-AESFileStream {
<#
    .SYNOPSIS

        Author: Alexander Rymdeko-Harvey (@Killswitch-GUI)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Uses .NET to decrypt using file stream rather than fully in mem.

        Refrence: https://stackoverflow.com/questions/1153126/how-to-create-a-zip-archive-with-powershell
                  https://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptostream.cryptostream(v=vs.110).aspx
                  https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d


    .PARAMETER DestionationDirectory

        Required Destionation directory of file to be placed on disk
    
    .PARAMETER DestionationFile

        Required Destionation file name to be placed on disk

    .PARAMETER EncryptedFileName

        Required encrypted file name 

    .PARAMETER EncryptedFilePath

        Required encrypted file path

    .PARAMETER AesKey

        Required AES key to be used for decryption
    
    .NOTES
        
        Adapted from Tyler Siegrist.

    .EXAMPLE

        Decrypt-AESFileStream -DestionationDirectory 'C:\Users\admin\Desktop\' -DestionationFile 'secrets2.txt' -EncryptedFileName 'secrets.crypto' -EncryptedFilePath 'C:\Users\admin\Desktop\' -AesKey 7f/3e9cQF8yx2UNhG/Dc6XYLKYqXptK1ALB+tP3QUwA= -Verbose
        
        Computer     Key                                          Files
        --------     ---                                          -----
        RYMDEKO-TEST 7f/3e9cQF8yx2UNhG/Dc6XYLKYqXptK1ALB+tP3QUwA= C:\Users\admin\Desktop\secrets2.txt

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $DestionationDirectory,

        [Parameter(Mandatory = $true, Position = 1)]
        [String]
        $DestionationFile,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $EncryptedFileName,

        [Parameter(Mandatory = $true, Position = 3)]
        [string]
        $EncryptedFilePath,

        [Parameter(Mandatory = $true, Position = 4)]
        [string]
        $AesKey
    )

    Begin {
        $ErrorActionPreference = "Stop"
        $EncryptedFile = "$EncryptedFilePath$EncryptedFileName"
        $FileName = "$DestionationDirectory$DestionationFile"
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
        $AESProvider = Create-AesManagedObject -AesKey $AesKey
    }
    
    Process {
        # create the file stream for the encryptor
        Try
        {
            $FileStreamReader = New-Object System.IO.FileStream($EncryptedFile, [System.IO.FileMode]::Open)
        }
        Catch
        {
            Write-Error "[!] Unable to open file stream object: $EncryptedFile "
            exit
        }
        # create destination file
        Try
        {
            $FileStreamWriter = New-Object System.IO.FileStream($FileName, [System.IO.FileMode]::Create)
        }
        Catch
        {
            Write-Error "[!] Unable to open file to write: $FileStreamWriter"
            $FileStreamReader.Close()
            $FileStreamWriter.Close()
            exit
        }
        #Get IV
        try
        {
            [Byte[]]$LenIV = New-Object Byte[] 4
            $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
            $FileStreamReader.Read($LenIV,  0, 3) | Out-Null
            [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0)
            [Byte[]]$IV = New-Object Byte[] $LIV
            $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
            $FileStreamReader.Read($IV, 0, $LIV) | Out-Null
            $AESProvider.IV = $IV
             Write-Verbose "[*] Decrypting $EncryptedFile with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

        }
        catch
        {
            Write-Error '[!] Bad IV or File coruption of IV header, check back to backup data returned from encryption.'
            return
        }

        # decrypt routine
        try
        {
            $Transform = $AESProvider.CreateDecryptor()
            [Int]$Count = 0
            [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
            [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            Do
            {
                $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                $CryptoStream.Write($Data, 0, $Count)
            }
            While ($Count -gt 0)

            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()
            Write-Verbose "Successfully decrypted file: $EncryptedFile"
        }
        catch
        {
            Write-Error "Failed to decrypt $EncryptedFile"
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()
            Remove-Item $FileName -Force
        } 
    }

    End {
        $len = (Get-Item "$FileName").length
        # TODO: re write the add-type before using this
        # $size = Convert-Size -Size $len
        $size = $len
        Write-Verbose "[*] Final decrypted file size: $size"
        $Result = New-Object –TypeName PSObject
        $Result | Add-Member –MemberType NoteProperty –Name Computer –Value $env:COMPUTERNAME
        $Result | Add-Member –MemberType NoteProperty –Name Key –Value $AesKey
        $Result | Add-Member –MemberType NoteProperty –Name Files –Value $FileName
        return $Result
    }
    

}

