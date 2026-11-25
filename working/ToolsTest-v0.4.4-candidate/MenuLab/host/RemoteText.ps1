# P011 host-only shell text parser v0.3.1.
# This file never invokes adb, opens devices, starts processes, or writes files.
# Only TEXT protocol output is normalized. Never use this for binary adb payloads.
Set-StrictMode -Version 2.0
function ConvertTo-P011CanonicalText {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    # Treat CR+LF, CRCR+LF and LF as a single line end; keep raw text separately.
    $normalized = [regex]::Replace($Text, '\r+\n', "`n")
    return $normalized.Replace("`r", "`n")
}
function Read-P011ExitEnvelope {
    param(
        [AllowEmptyString()][string]$Text,
        [string]$Marker = '__P011_REMOTE_EXIT__='
    )
    if ($Marker -cnotmatch '\A__P011_REMOTE_EXIT(?:_[0-9a-fA-F]{32})?__=\z') {
        throw 'REMOTE_MARKER_INVALID: expected the exact marker for this call.'
    }
    $normalized = ConvertTo-P011CanonicalText -Text $Text
    $prefixPattern = '(?m)^' + [regex]::Escape($Marker)
    $markerLines = [regex]::Matches($normalized, $prefixPattern)
    $validLines = [regex]::Matches($normalized, $prefixPattern + '([0-9]{1,3})[ \t]*$')
    if ($markerLines.Count -ne 1 -or $validLines.Count -ne 1) {
        throw ('REMOTE_MARKER_MISSING_OR_AMBIGUOUS: starts={0}; complete={1}' -f $markerLines.Count,$validLines.Count)
    }
    $m = $validLines[0]
    $code = [int]$m.Groups[1].Value
    if ($code -gt 255) { throw 'REMOTE_EXIT_OUT_OF_RANGE: shell status must be 0..255.' }
    $suffix = $normalized.Substring($m.Index + $m.Length)
    if ($suffix -cnotmatch '\A[ \t\n]*\z') {
        throw 'REMOTE_MARKER_NOT_FINAL: non-whitespace followed the terminal status.'
    }
    return [PSCustomObject]@{
        Text=$normalized.Substring(0,$m.Index).Trim()
        Exit=$code
        Normalized=$normalized
        NormalizationChanged=($normalized -cne $Text)
        RawCharacters=$Text.Length
        NormalizedCharacters=$normalized.Length
        CRCount=[regex]::Matches($Text, '\r').Count
        LFCount=[regex]::Matches($Text, '\n').Count
        Marker=$Marker
    }
}
function Test-P011RemoteText {
    # Offline tests run automatically before any adb call in the host launcher.
    $fixed='__P011_REMOTE_EXIT__='
    $unique='__P011_REMOTE_EXIT_0123456789abcdef0123456789abcdef__='
    $records=[Collections.Generic.List[object]]::new()
    $cases=@(
        @{Name='LF';Text="0`n`n${fixed}0`n";Marker=$fixed;Accept=$true;Code=0;Body='0'},
        @{Name='CRLF';Text="0`r`n`r`n${fixed}0`r`n";Marker=$fixed;Accept=$true;Code=0;Body='0'},
        @{Name='CAPTURED_CRCRLF';Text="0`r`r`n`r`r`n${fixed}0`r`r`n";Marker=$fixed;Accept=$true;Code=0;Body='0'},
        @{Name='TRIPLE_CRLF';Text="0`r`r`r`n${fixed}0`r`r`r`n";Marker=$fixed;Accept=$true;Code=0;Body='0'},
        @{Name='CR_ONLY';Text="0`r${fixed}0`r";Marker=$fixed;Accept=$true;Code=0;Body='0'},
        @{Name='FINAL_NO_NEWLINE';Text="0`n${fixed}0";Marker=$fixed;Accept=$true;Code=0;Body='0'},
        @{Name='TRAILING_BLANKS';Text="0`n${fixed}0 `t`r`r`n `n";Marker=$fixed;Accept=$true;Code=0;Body='0'},
        @{Name='EMPTY_BODY';Text="`n${fixed}0`n";Marker=$fixed;Accept=$true;Code=0;Body=''},
        @{Name='NONZERO_PRESERVED';Text="failure`r`r`n${fixed}7`r`r`n";Marker=$fixed;Accept=$true;Code=7;Body='failure'},
        @{Name='EXIT_255';Text="x`n${fixed}255`n";Marker=$fixed;Accept=$true;Code=255;Body='x'},
        @{Name='EXACT_NONCE';Text="0`r`r`n${unique}0`r`r`n";Marker=$unique;Accept=$true;Code=0;Body='0'},
        @{Name='NO_MARKER';Text="0`n";Marker=$fixed;Accept=$false},
        @{Name='DUPLICATE';Text="${fixed}0`n${fixed}0`n";Marker=$fixed;Accept=$false},
        @{Name='OUT_OF_RANGE';Text="${fixed}256`n";Marker=$fixed;Accept=$false},
        @{Name='BAD_STATUS';Text="${fixed}abc`n";Marker=$fixed;Accept=$false},
        @{Name='NEGATIVE_STATUS';Text="${fixed}-1`n";Marker=$fixed;Accept=$false},
        @{Name='UNICODE_DIGIT';Text=($fixed+[char]0x0660+"`n");Marker=$fixed;Accept=$false},
        @{Name='NOT_FINAL';Text="${fixed}0`nmore text`n";Marker=$fixed;Accept=$false},
        @{Name='INLINE_MARKER';Text="echo ${fixed}0`n";Marker=$fixed;Accept=$false},
        @{Name='WRONG_NONCE';Text="0`n${fixed}0`n";Marker=$unique;Accept=$false},
        @{Name='TRUNCATED_STATUS';Text=$fixed;Marker=$fixed;Accept=$false},
        @{Name='VALID_PLUS_MALFORMED';Text="${fixed}bad`n${fixed}0`n";Marker=$fixed;Accept=$false}
    )
    foreach ($case in $cases) {
        $got=$null; $errorText=''
        try { $got=Read-P011ExitEnvelope -Text $case.Text -Marker $case.Marker }
        catch { $errorText=$_.Exception.Message }
        if ($case.Accept) {
            if ($null -eq $got -or $got.Exit -ne $case.Code -or $got.Text -cne $case.Body) {
                throw ('PARSER_SELFTEST_FAILED: {0}; {1}' -f $case.Name,$errorText)
            }
        } elseif ($null -ne $got) { throw ('PARSER_SELFTEST_FAILED: invalid envelope accepted: '+$case.Name) }
        [void]$records.Add([PSCustomObject]@{case=$case.Name;pass=$true;accepted=($null -ne $got)})
    }
    return $records.ToArray()
}
