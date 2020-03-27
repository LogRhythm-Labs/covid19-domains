param(
    [Parameter()][string]$OutputFilePath,
    [Parameter()][string]$OutputFileName,
    [Parameter()][string]$TempDir,
    [Parameter()][switch]$DoPrepend
)

# ================= COVID-19 Malicious Domain List Importer PowerShell Script =================
#
#   A PowerShell script that automatically pulls the latest copy of a RiskIQ list of recent malicious COVID-19-related domains and builds a list file for import within the LogRhythm SIEM
#
#   Script Copyright March 2020 - LogRhythm Labs/LogRhythm Office of the CISO - LogRhythm, Inc.
#
#   Domain/list data provided by RiskIQ - Copyright March 2020/All Rights Reserved RiskIQ. The data provided by RiskIQ is a free service/data set and may be terminated or removed at any time without warning


# ======= Example usage:
#
#   If no custom output file path and file name are specified, the script will write the output file to the default LR list auto import directory
#
#   PS> covid19_domains.ps1 -OutputFileName "covid_custom_list_name.txt"
#   PS> covid19_domains.ps1 -OutputFilePath "C:\Users\zack.rowland\Documents\lists" -OutputFileName "covid_test_list.txt"


# ======= Globals/Parameters/Etc.
#
#   Default path and filename for the LR list file that we'll create (used if no args specified)


$outListFile = "C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import"
$covidTmpDir = "C:\Program Files\LogRhythm\LogRhythm Job Manager\config\covid_temp"
$outListFileName = "covid_domains.txt"

if ($TempDir -ne "")
{
    $covidTmpDir = $TempDir
}

if ([System.IO.Directory]::Exists($covidTmpDir) -eq $false)
{
    [System.IO.Directory]::CreateDirectory($covidTmpDir) 1> $null
}

if ($OutputFilePath -ne "")
{
    $outListFile = $OutputFilePath
}

if ($OutputFileName -ne "")
{
    $outListFileName = $OutputFileName
}

$outputFullPath = [System.IO.Path]::Combine($outListFile,$outListFileName)
$outputTempFullPath = [System.IO.Path]::Combine($covidTmpDir,$outlistFileName)

# ======= Pull XML File, find latest CoVid list

$uri = 'https://covid-public-domains.s3-us-west-1.amazonaws.com/'
$xmld = Invoke-RestMethod -Method Get -Uri $uri -SessionVariable sv -ErrorAction Ignore
$xmlroot = $xmld.DocumentElement
$dateNow = [System.DateTime]::Now
$dateLatest = [System.DateTime]::MinValue
$covidLatest = "none"
foreach ($c in $xmlroot.Contents)
{
    if ($c.Key -match "covid.*")
    {
        $tmpCoName = $c.Key
        $tmpDateStr = $c.LastModified
        $tmpDate = [System.DateTime]::Parse($tmpDateStr)
        if ($tmpDate -gt $dateLatest)
        {
            $dateLatest = $tmpDate
            $covidLatest = $tmpCoName
        }
    }
}

Write-Host -ForegroundColor Green "Found latest covid domain file: ${dateLatest}: ${covidLatest}"

if ($covidLatest -eq "none")
{
    Write-Error "Unable to find any file listings in XML file!"
    return 1
}

$latestUri = $($uri + $covidLatest)
$covidLatestPath = [System.IO.Path]::Combine($covidTmpDir,$covidLatest)
$respCovidFile = Invoke-WebRequest -Uri $latestUri -Method Get -OutFile $covidLatestPath -ErrorAction Ignore

# To do: Need to add error handling here in case web req fails

$csv = Import-Csv -Path $covidLatestPath

# Test filter that also only outputs domains with "flu" in the name; generates a much shorter list, helpful for testing purposes
#$covidEntries = $($csv | Where { $_.Query -ne "virus" -and $_.Match -match "flu" } | Select -Unique Match)

$covidEntries = $($csv | Where { $_.Query -ne "virus" } | Select -Unique Match)

# Create a list object that will contain the final/master list of entries

$covidList = New-Object System.Collections.Generic.List[string]

# Set up an array of prefixes we'll add to each entry (only used if the "-DoPrepend" flag is enabled at run time)

$prefixList = "http://","https://"

foreach ($entry in $covidEntries)
{
    $entryMain = $entry.Match

    # Filter out or modify certain entries for compatibility with LR (e.x. "*.domain.com" won't work in a list)
    #
    # Current Filters:
    # Domains beginning with "*."
    # Any instance of the ASCII escape "\032", seen alone or with a complete/incomplete IP address in front of it

    if ($entryMain -match "(?:^\*\.|\\032)")
    {
        # The entry contains an illegal char/strange formatting/etc. and needs to be dealt with

        if ($entryMain -match "^\*\.")
        {
            $entryMain = [Regex]::Replace($entryMain,"^\*\.","www.",[System.Text.RegularExpressions.RegexOptions]::None)
        }

        if ($entryMain -match "\d+\.\d+\.\d+(?:\.\d+)?\\032")
        {
            $entryMain = [Regex]::Replace($entryMain,"\d+\.\d+\.\d+(?:\.\d+)?\\032","",[System.Text.RegularExpressions.RegexOptions]::None)
        }

        if ($entryMain -match "\\032")
        {
            $entryMain = [Regex]::Replace($entryMain,"\\032","",[System.Text.RegularExpressions.RegexOptions]::None)
        }

        $covidList.Add($entryMain)
        if ($DoPrepend)
        {
            foreach ($p in $prefixList)
            {
                $covidList.Add($($p+$entryMain))
            }
        }
    }
    else
    {
        # The entry didn't contain any illegal chars, etc. so we proceed with adding it to the main list

        $covidList.Add($entryMain)

        if ($DoPrepend)
        {
            foreach ($p in $prefixList)
            {
                $covidList.Add($($p+$entryMain))
            }
        }
    }
}

Write-Host -ForegroundColor Green "Completed building domain list"

# Delete old list

[System.IO.File]::Delete($outputTempFullPath)

# Write final list file

foreach ($cl in $covidList)
{
    Write-Output -InputObject $cl | Out-File -FilePath $outputTempFullPath -Append
}

Write-Host -ForegroundColor Green "Wrote LR list text file to temp folder: ${outputTempFullPath}"

# Copy final list file to LR list auto import directory

[System.IO.File]::Copy($outputTempFullPath,$outputFullPath)
Write-Host -ForegroundColor Green "Copied list text file to list auto-import directory"


Write-Host -ForegroundColor Green "Done!"
# SIG # Begin signature block
# MIIcdQYJKoZIhvcNAQcCoIIcZjCCHGICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7zuVYmc0XOzDPDwJ+OCXVBwL
# rO6gghebMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTKMIIDsqADAgECAhA7fcSpOOvoChwkFo65IyOmMA0GCSqGSIb3DQEBCwUAMH8x
# CzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0G
# A1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UEAxMnU3ltYW50ZWMg
# Q2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBMB4XDTE3MDQwNDAwMDAwMFoX
# DTIwMDQwNDIzNTk1OVowYjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRv
# MRAwDgYDVQQHDAdCb3VsZGVyMRYwFAYDVQQKDA1Mb2dSaHl0aG0gSW5jMRYwFAYD
# VQQDDA1Mb2dSaHl0aG0gSW5jMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEArr9SaqNn81S+mF151igpNeqvzWs40uPSf5tXu9iQUqXCWx25pECOcNk7W/Z5
# O9dXiQmdIvIFF5FqCkP6rzYtKx3OH9xIzoSlOKTxRWj3wo+R1vxwT9ThOvYiz/5T
# G5TJZ1n4ILFTd5JexoS9YTA7tt+2gbDtjKLBorYUCvXv5m6PREHpZ0uHXGCDWrJp
# zhiYQdtyAfxGQ6J9SOekYu3AiK9Wf3nbuoxLDoeEQ4boFW3iQgYJv1rRFA1k4AsT
# nsxDmEhd9enLZEQd/ikkYrIwkPVN9rPH6B+uRsBxIWIy1PXHwyaCTO0HdizjQlhS
# RaV/EzzbyTMPyWNluUjLWe0C4wIDAQABo4IBXTCCAVkwCQYDVR0TBAIwADAOBgNV
# HQ8BAf8EBAMCB4AwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N2LnN5bWNiLmNv
# bS9zdi5jcmwwYQYDVR0gBFowWDBWBgZngQwBBAEwTDAjBggrBgEFBQcCARYXaHR0
# cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9ycGEwEwYDVR0lBAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUHAQEESzBJ
# MB8GCCsGAQUFBzABhhNodHRwOi8vc3Yuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpo
# dHRwOi8vc3Yuc3ltY2IuY29tL3N2LmNydDAfBgNVHSMEGDAWgBSWO1PweTOXr32D
# 7y4rzMq3hh5yZjAdBgNVHQ4EFgQUf2bE5CWM4/1XmNZgr/W9NahQJkcwDQYJKoZI
# hvcNAQELBQADggEBAHfeSWKiWK1eI+cD/1z/coADJfCnPynzk+eY/MVh0jOGM2dJ
# eu8MBcweZdvjv4KYN/22Zv0FgDbwytBFgGxBM6pSRU3wFJN9XroLJCLAKCmyPN7H
# IIaGp5RqkeL4jgKpB5R6NqSb3ES9e2obzpOEvq49nPCSCzdtv+oANVYj7cIxwBon
# VvIqOZFxM9Bj6tiMDwdvtm0y47LQXM3+gWUHNf5P7M8hAPw+O2t93hPmd2xA3+U7
# FqUAkhww4IhdIfaJoxNPDjQ4dU+dbYL9BaDfasYQovY25hSe66a9S9blz9Ew2uNR
# iGEvYMyxaDElEXfyDSTnmR5448q1jxFpY5giBY0wggTTMIIDu6ADAgECAhAY2tGe
# Jn3ou0ohWM3MaztKMA0GCSqGSIb3DQEBBQUAMIHKMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5l
# dHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1
# dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVi
# bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0wNjEx
# MDgwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdv
# cmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhv
# cml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGlj
# IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAK8kCAgpejWeYAyq50s7Ttx8vDxFHLsr4P4p
# AvlXCKNkhRUn9fGtyDGJXSLoKqqmQrOP+LlVt7G3S7P+j34HV+zvQ9tmYhVhz2AN
# pNje+ODDYgg9VBPrScpZVIUm5SuPG5/r9aGRwjNJ2ENjalJL0o/ocFFN0Ylpe8dw
# 9rPcEnTbe11LVtOWvxV3obD0oiXyrxySZxjl9AYE75C55ADk3Tq1Gf8CuvQ87uCL
# 6zeL7PTXrPL28D2v3XWRMxkdHEDLdCQZIZPZFP6sKlLHj9UESeSNY0eIPGmDy/5H
# vSt+T8WVrg6d1NFDwGdz4xQIfuU/n3O4MwrPXT80h5aK7lPoJRUCAwEAAaOBsjCB
# rzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARh
# MF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvD
# z4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdp
# ZjAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQAD
# ggEBAJMkSjBfYs/YGpgvPercmS29d/aleSI47MSnoHgSrWIORXBkxeeXZi2YCX5f
# r9bMKGXyAaoIGkfe+fl8kloIaSAN2T5tbjwNbtjmBpFAGLn4we3f20Gq4JYgyc1k
# FTiByZTuooQpCxNvjtsM3SUC26SLGUTSQXoFaUpYT2DKfoJqCwKqJRc5tdt/54Rl
# KpWKvYbeXoEWgy0QzN79qIIqbSgfDQvE5ecaJhnh9BFvELWV/OdCBTLbzp1RXii2
# noXTW++lfUVAco63DmsOBvszNUhxuJ0ni8RlXw2GdpxEevaVXPZdMggzpFS2GD9o
# XPJCSoU4VINf0egs8qwR1qjtY2owggVZMIIEQaADAgECAhA9eNf5dklgsmF99PAe
# yoYqMA0GCSqGSIb3DQEBCwUAMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVy
# aVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4
# BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQg
# dXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGljIFByaW1h
# cnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0xMzEyMTAwMDAwMDBa
# Fw0yMzEyMDkyMzU5NTlaMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEw
# MC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENB
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl4MeABavLLHSCMTXaJNR
# YB5x9uJHtNtYTSNiarS/WhtR96MNGHdou9g2qy8hUNqe8+dfJ04LwpfICXCTqdpc
# DU6kDZGgtOwUzpFyVC7Oo9tE6VIbP0E8ykrkqsDoOatTzCHQzM9/m+bCzFhqghXu
# PTbPHMWXBySO8Xu+MS09bty1mUKfS2GVXxxw7hd924vlYYl4x2gbrxF4GpiuxFVH
# U9mzMtahDkZAxZeSitFTp5lbhTVX0+qTYmEgCscwdyQRTWKDtrp7aIIx7mXK3/nV
# jbI13Iwrb2pyXGCEnPIMlF7AVlIASMzT+KV93i/XE+Q4qITVRrgThsIbnepaON2b
# 2wIDAQABo4IBgzCCAX8wLwYIKwYBBQUHAQEEIzAhMB8GCCsGAQUFBzABhhNodHRw
# Oi8vczIuc3ltY2IuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwbAYDVR0gBGUwYzBh
# BgtghkgBhvhFAQcXAzBSMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LnN5bWF1dGgu
# Y29tL2NwczAoBggrBgEFBQcCAjAcGhpodHRwOi8vd3d3LnN5bWF1dGguY29tL3Jw
# YTAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2IuY29tL3BjYTMtZzUu
# Y3JsMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMC
# AQYwKQYDVR0RBCIwIKQeMBwxGjAYBgNVBAMTEVN5bWFudGVjUEtJLTEtNTY3MB0G
# A1UdDgQWBBSWO1PweTOXr32D7y4rzMq3hh5yZjAfBgNVHSMEGDAWgBR/02Wnwt3s
# u/AwCfNDOfoCrzMxMzANBgkqhkiG9w0BAQsFAAOCAQEAE4UaHmmpN/egvaSvfh1h
# U/6djF4MpnUeeBcj3f3sGgNVOftxlcdlWqeOMNJEWmHbcG/aIQXCLnO6SfHRk/5d
# yc1eA+CJnj90Htf3OIup1s+7NS8zWKiSVtHITTuC5nmEFvwosLFH8x2iPu6H2aZ/
# pFalP62ELinefLyoqqM9BAHqupOiDlAiKRdMh+Q6EV/WpCWJmwVrL7TJAUwnewus
# GQUioGAVP9rJ+01Mj/tyZ3f9J5THujUOiEn+jf0or0oSvQ2zlwXeRAwV+jYrA9zB
# UAHxoRFdFOXivSdLVL4rhF4PpsN0BQrvl8OJIrEfd/O9zUPU8UypP7WLhK9k8tAU
# ITGCBEQwggRAAgEBMIGTMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEw
# MC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENB
# AhA7fcSpOOvoChwkFo65IyOmMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBReFttTvKBqasP2nYqG
# dottSPPJhTANBgkqhkiG9w0BAQEFAASCAQANVtKbo8FMOAQ9d4GA9mUqx3+cyhb6
# HYn0LjrVvSV36ilnEDVPWC/6thWaIO6byjen4yciCN2TBdcUvr2zWy2Q4wTV/gqK
# imu4QaElnHKhnmZZyZPs0O6Hi+Mcdc7A9IUKyWFmKHMqa1hDCXJBqJBxZb1k6FHj
# GsN2l1e7KoCIKn0m3NUYlE1SErM2I5l8QZtKryLSwGEHOoK4ux4fEUMnmRv8cx8F
# EhZcVfnyPPKQbmz3vT011y37yzJPKvstrKcf3EFmSUBtYlbbsjKY/pO/mBRh8AIC
# B2zXRxT6PmcvEhQBFclKSuQcQ7TfAwoMSqAWi+vtEAsYJlxM4Wch26pooYICCzCC
# AgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRlYyBUaW1l
# IFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P9DjI/r81bgTYapgbGlAwCQYF
# Kw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkF
# MQ8XDTIwMDMyNzE2NDQxNlowIwYJKoZIhvcNAQkEMRYEFNb0d/PLMVopr/QEGQIh
# LjqUYk94MA0GCSqGSIb3DQEBAQUABIIBAHUwuqXdXVxIc7+FUCkfxZqFiLf/yOdn
# otp1YjONlaFKfP9fJ8IiYZIoq7/kpVnyQW5gSLBfcwelC/vj0zY25Q/PFRbgoObw
# S+hR/pG9DBbzwEJ/w1lLLfLxcG5ZcQGm6t1ZB5FLr/KxD4hZYyGGKobJokW1Pl9Q
# jdLsxA71S/obpwCj11MHXRbUZxOZaI9d6hhmStw5Ok2mfF6OHxoBwYS8gKEbKgKW
# Ai6uj+wdWNINvWpRl8AeFwZc5Z12sOh/sBfc9A/lF4No7cwutXU3LF16NzIbA82W
# zI0OgZ/0tJPLi5PIsrXfEOeRaRFMiQdY998jfaUeztCtiL20UbvMWBg=
# SIG # End signature block
