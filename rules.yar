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

// === NEW ENHANCED RULES FOR MODERN THREATS ===

rule Modern_C2_Channels {
    meta:
        description = "Detects modern C2 communication channels"
        author = "Enhanced Scanner"
    strings:
        $pastebin = /https:\/\/pastebin\.com\/raw\/[A-Za-z0-9]{8}/
        $github_raw = /https:\/\/raw\.githubusercontent\.com\/[^\/]+\/[^\/]+\/[^\/]+/
        $ipfs_hash = /Qm[1-9A-HJ-NP-Za-km-z]{44}/
        $mega_nz = /https:\/\/mega\.nz\/#[!A-Za-z0-9_-]+/
        $onedrive = /https:\/\/1drv\.ms\/[a-z]\/[A-Za-z0-9_-]+/
        $dropbox = /https:\/\/dropbox\.com\/s\/[A-Za-z0-9]+\//
    condition:
        any of them
}

rule Cloud_Storage_Exfiltration {
    meta:
        description = "Detects cloud storage exfiltration patterns"
        author = "Enhanced Scanner"
    strings:
        $gdrive_api = /https:\/\/drive\.google\.com\/file\/d\/[A-Za-z0-9_-]+/
        $box_share = /https:\/\/[^.]+\.box\.com\/s\/[A-Za-z0-9]+/
        $wetransfer = /https:\/\/we\.tl\/[A-Za-z0-9]+/
        $temp_email = /10minutemail|guerrillamail|mailinator|tempmail/
        $file_upload = /file\.io|transfer\.sh|0x0\.st/
    condition:
        any of them
}

rule Cryptocurrency_Mining_References {
    meta:
        description = "Detects cryptocurrency mining references"
        author = "Enhanced Scanner"
    strings:
        $monero_addr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
        $pool_mining = /pool\.mining|mining\.pool|stratum\+tcp/
        $xmrig = "xmrig"
        $cpuminer = "cpuminer"
        $mining_algo = /cryptonight|randomx|ethash|kawpow/
        $wallet_mining = /wallet.*mining|mining.*wallet/
    condition:
        any of them
}

rule NFT_Blockchain_References {
    meta:
        description = "Detects NFT and blockchain references"
        author = "Enhanced Scanner"
    strings:
        $opensea = /opensea\.io\/assets\/[^\/]+\/[^\/]+\/[0-9]+/
        $contract_addr = /0x[a-fA-F0-9]{40}/
        $ens_domain = /[a-zA-Z0-9-]+\.eth/
        $ipfs_gateway = /ipfs\.io\/ipfs\/[A-Za-z0-9]+/
        $nft_metadata = /"name":\s*"[^"]+",\s*"description":\s*"[^"]+",\s*"image":/
        $smart_contract = /pragma solidity|contract.*{|function.*public/
    condition:
        any of them
}

rule Advanced_Obfuscation_Techniques {
    meta:
        description = "Detects advanced obfuscation techniques"
        author = "Enhanced Scanner"
    strings:
        $unicode_escape = /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/
        $rot13_like = /nopqrstuvwxyzabcdefghijklm/
        $base32_long = /[A-Z2-7]{100,}={0,6}/
        $base85_marker = /<~.*~>/
        $hex_obfusc = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){20,}/
        $xor_pattern = /xor.*0x[0-9a-fA-F]+|[0-9a-fA-F]+.*xor/
    condition:
        any of them
}

rule Social_Engineering_Keywords {
    meta:
        description = "Detects social engineering keywords"
        author = "Enhanced Scanner"
    strings:
        $urgent = /urgent.*action|immediate.*response|act.*now/
        $verify = /verify.*account|confirm.*identity|update.*payment/
        $security = /security.*alert|account.*suspended|unauthorized.*access/
        $winner = /congratulations.*winner|you.*won|claim.*prize/
        $covid = /covid.*relief|pandemic.*assistance|vaccine.*appointment/
        $crypto_promise = /guaranteed.*profit|crypto.*investment|bitcoin.*returns/
    condition:
        any of them
}

rule Remote_Access_Tools {
    meta:
        description = "Detects remote access tool references"
        author = "Enhanced Scanner"
    strings:
        $teamviewer = "teamviewer"
        $anydesk = "anydesk"
        $rdp_connect = /mstsc|remote.*desktop|rdp.*connect/
        $vnc_connect = /vnc.*viewer|tightvnc|realvnc/
        $ssh_tunnel = /ssh.*tunnel|putty.*tunnel/
        $ngrok = "ngrok"
        $reverse_shell = /reverse.*shell|shell.*reverse/
    condition:
        any of them
}

rule AI_Generated_Content_Markers {
    meta:
        description = "Detects AI-generated content markers"
        author = "Enhanced Scanner"
    strings:
        $ai_disclaimer = /generated.*ai|ai.*generated|artificial.*intelligence.*created/
        $deepfake = /deepfake|face.*swap|synthetic.*media/
        $gpt_marker = /chatgpt|gpt-[0-9]|openai.*model/
        $stable_diffusion = /stable.*diffusion|dall.*e|midjourney/
        $synthetic_id = /synthetic.*identity|fake.*person|generated.*face/
    condition:
        any of them
}

rule Suspicious_Base64_Patterns {
    meta:
        description = "Detects suspicious base64 encoded content patterns"
        author = "Enhanced Scanner"
    strings:
        $b64_powershell = /cG93ZXJzaGVsbA|cG93ZXJzaGVsb|UG93ZXJTaGVsbA/  // powershell variations
        $b64_cmd = /Y21kLmV4ZQ|Y21k|Q21kLmV4ZQ/  // cmd.exe variations
        $b64_wget = /d2dldA|V2dldA|d2VnZXQ/  // wget variations
        $b64_curl = /Y3VybA|Q3VybA|Y3VybC|Curl/  // curl variations
        $b64_http = /aHR0cDovL|aHR0cHM6Ly|SFRUUDovL/  // http/https
        $b64_invoke = /SW52b2tl|aW52b2tl|SU5WT0tF/  // Invoke variations
    condition:
        any of them
}

rule Polyglot_File_Indicators {
    meta:
        description = "Detects polyglot file indicators"
        author = "Enhanced Scanner"
    strings:
        $pdf_in_image = "%PDF-"
        $zip_in_image = { 50 4B 03 04 }
        $html_in_image = "<html" nocase
        $javascript_in_image = "<script" nocase
        $xml_in_image = "<?xml" nocase
        $svg_in_image = "<svg" nocase
    condition:
        any of them and (
            uint16(0) == 0xD8FF or  // JPEG
            uint32(0) == 0x474E5089 or  // PNG
            uint32(0) == 0x38464947  // GIF
        )
}