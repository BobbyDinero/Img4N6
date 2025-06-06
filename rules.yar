rule Suspicious_EXIF_Commands {
    meta:
        description = "Detects command execution in EXIF metadata fields"
    strings:
        $cmd1 = "cmd.exe"
        $cmd2 = "powershell.exe"
        $cmd3 = "powershell -e"
        $cmd4 = "powershell -enc"
        $cmd5 = "curl -o"
        $cmd6 = "wget -O"
        $cmd7 = "nc.exe"
        $cmd8 = "netcat"
        $cmd9 = "certutil -decode"
        $cmd10 = "bitsadmin /transfer"
    condition:
        any of them
}

rule Embedded_PE_Executables {
    meta:
        description = "Detects embedded Windows executables at file start"
    strings:
        $mz = { 4D 5A }  // "MZ" header
        $pe = { 50 45 00 00 }  // "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule Archive_Files_Embedded {
    meta:
        description = "Detects embedded archive files at start of image"
    strings:
        $zip = { 50 4B 03 04 }
        $rar = { 52 61 72 21 1A 07 00 }
        $7z = { 37 7A BC AF 27 1C }
    condition:
        any of them at 0
}

rule Clear_Text_Crypto_Wallets {
    meta:
        description = "Detects cryptocurrency wallet addresses in clear text"
    strings:
        $btc_label = /[Bb]itcoin.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $eth_label = /[Ee]thereum.*0x[a-fA-F0-9]{40}/
        $wallet_label = /[Ww]allet.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $address_label = /[Aa]ddress.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        any of them
}

rule Malicious_URLs_Clear {
    meta:
        description = "Detects malicious URLs in clear text"
    strings:
        $discord_webhook = /https:\/\/discord(app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/
        $telegram_bot = /https:\/\/api\.telegram\.org\/bot\d+:[A-Za-z0-9_-]+/
        $suspicious_tld1 = /https?:\/\/[a-zA-Z0-9.-]+\.tk\/[^\s]+/
        $suspicious_tld2 = /https?:\/\/[a-zA-Z0-9.-]+\.ml\/[^\s]+/
        $suspicious_tld3 = /https?:\/\/[a-zA-Z0-9.-]+\.ga\/[^\s]+/
        $ip_url = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[^\s"'<>]+/
    condition:
        any of them
}

rule Social_Media_API_Tokens {
    meta:
        description = "Detects social media API tokens"
    strings:
        $github_token = /gh[pousr]_[A-Za-z0-9]{36}/
        $slack_token = /xox[baprs]-[A-Za-z0-9-]{10,72}/
        $discord_token = /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}/
        $telegram_token = /\d{9}:[A-Za-z0-9_-]{35}/
        $twitter_bearer = /Bearer [A-Za-z0-9%]{100,}/
    condition:
        any of them
}

rule PowerShell_Obfuscation {
    meta:
        description = "Detects PowerShell obfuscation in metadata"
    strings:
        $ps_b64 = "FromBase64String"
        $ps_invoke = "Invoke-Expression"
        $ps_iex = " IEX "
        $ps_encoded = "-EncodedCommand"
        $ps_bypass = "-ExecutionPolicy Bypass"
        $ps_hidden = "-WindowStyle Hidden"
        $ps_noprofile = "-NoProfile"
    condition:
        any of them
}

rule Script_Injection_HTML {
    meta:
        description = "Detects HTML/JavaScript injection"
    strings:
        $script_tag = "<script"
        $script_close = "</script>"
        $js_proto = "javascript:"
        $js_eval = "eval("
        $js_write = "document.write("
        $js_location = "window.location"
        $js_href = "location.href"
    condition:
        any of them
}

rule Windows_Registry_Persistence {
    meta:
        description = "Detects Windows registry persistence mechanisms"
    strings:
        $run_key1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $run_key2 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $runonce_key1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        $runonce_key2 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        $startup_folder = "\\Start Menu\\Programs\\Startup\\"
    condition:
        any of them
}

rule Suspicious_File_Extensions_Context {
    meta:
        description = "Detects suspicious file extensions with context"
    strings:
        $download1 = "download" nocase
        $execute1 = "execute" nocase
        $run1 = "run" nocase
        $file_exe = ".exe"
        $file_scr = ".scr"
        $file_bat = ".bat"
        $file_cmd = ".cmd"
        $file_vbs = ".vbs"
        $file_ps1 = ".ps1"
    condition:
        (any of ($download*, $execute*, $run*)) and any of ($file_*)
}

rule Email_Harvesting_Pattern {
    meta:
        description = "Detects email harvesting patterns"
    strings:
        $email_list = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[,;|\s]+[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        $mailto_multiple = /mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[,;]+/
    condition:
        any of them
}

rule Base64_Encoded_Executables {
    meta:
        description = "Detects base64 encoded executable headers"
    strings:
        $b64_mz1 = "TVo"     // "MZ" at start of base64
        $b64_mz2 = "TVp"     // "MZ" variant
        $b64_pe = "UEU"      // "PE" in base64
        $b64_elf = "f0VMR"   // ELF header in base64
    condition:
        any of them
}

rule Suspicious_Network_Commands {
    meta:
        description = "Detects network reconnaissance commands"
    strings:
        $net_ping = "ping -n"
        $net_nslookup = "nslookup"
        $net_telnet = "telnet"
        $net_nc = "nc -"
        $net_netstat = "netstat -"
        $net_arp = "arp -a"
        $net_ipconfig = "ipconfig /all"
        $net_whoami = "whoami /all"
    condition:
        any of them
}

rule Hex_Encoded_Strings_Long {
    meta:
        description = "Detects very long hexadecimal strings (likely encoded)"
    strings:
        $hex_string = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){50,}/
        $hex_array = /0x[0-9a-fA-F]{2}(,0x[0-9a-fA-F]{2}){50,}/
        $hex_plain = /[0-9a-fA-F]{300,}/
    condition:
        any of them
}

rule Steganography_References {
    meta:
        description = "Detects steganography tool references"
    strings:
        $steg_steghide = "steghide"
        $steg_outguess = "outguess"
        $steg_jphide = "jphide"
        $steg_jpseek = "jpseek"
        $steg_comment = "hidden message"
        $steg_extract = "extract"
        $steg_embed = "embed"
        $steg_password = "steg password"
    condition:
        any of ($steg_steghide, $steg_outguess, $steg_jphide, $steg_jpseek, $steg_password) or 
        (($steg_comment or $steg_extract or $steg_embed) and any of ($steg_steghide, $steg_outguess, $steg_jphide, $steg_jpseek))
}

rule GPS_Location_Data {
    meta:
        description = "Detects actual GPS location data in metadata"
    strings:
        $gps_lat = /GPS[A-Za-z]*Latitude[^0-9]*[-+]?[0-9]{1,3}\.[0-9]{4,}/
        $gps_lon = /GPS[A-Za-z]*Longitude[^0-9]*[-+]?[0-9]{1,3}\.[0-9]{4,}/
        $gps_coord = /GPS[A-Za-z]*[^0-9]*[-+]?[0-9]{1,3}\.[0-9]{4,}[^0-9]*[-+]?[0-9]{1,3}\.[0-9]{4,}/
        $exif_gps = "GPSInfo"
    condition:
        any of them
}