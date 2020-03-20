param(
    [Parameter()][string]$OutputFilePath,
    [Parameter()][string]$OutputFileName
)

# ================= COVID-19 Malicious Domain List Importer PowerShell Script =================
#
# A PowerShell script that automatically pulls the latest copy of a list of recent malicious COVID-19-related domains and builds a list file for import within the LogRhythm SIEM
#
# Copyright March 2020 - LogRhythm Labs/LogRhythm Office of the CISO - LogRhythm, Inc. 

# ======= Example usage:

# If no custom output file path and file name are specified, the script will write the output file to the default LR list auto import directory

# PS> covid19_domains.ps1 -OutputFileName "covid_custom_list_name.txt"
# PS> covid19_domains.ps1 -OutputFilePath "C:\Users\zack.rowland\Documents\lists" -OutputFileName "covid_test_list.txt"

# ======= Globals/Parameters/Etc.

# Default path and filename for the LR list file that we'll create (used if no args specified)

$outListFile = "C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import"
$outListFileName = "covid_domains.txt"

if ($OutputFilePath -ne "")
{
    $outListFile = $OutputFilePath
}

if ($OutputFileName -ne "")
{
    $outListFileName = $OutputFileName
}

$outputFullPath = [System.IO.Path]::Combine($outListFile,$outListFileName)

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

$respCovidFile = Invoke-WebRequest -Uri $latestUri -Method Get -OutFile "./${covidLatest}" -ErrorAction Ignore

# To do: Need to add error handling here in case web req fails

$csv = Import-Csv -Path "./${covidLatest}"

# Test filter that also only outputs domains with "flu" in the name; generates a much shorter list, helpful for testing purposes
#$covidEntries = $($csv | Where { $_.Query -ne "virus" -and $_.Match -match "flu" } | Select -Unique Match)

$covidEntries = $($csv | Where { $_.Query -ne "virus" } | Select -Unique Match)

# Create a list object that will contain the final/master list of entries

$covidList = New-Object System.Collections.Generic.List[string]

# Set up an array of prefixes we'll add to each entry

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
        foreach ($p in $prefixList)
        {
            $covidList.Add($($p+$entryMain))
        }
    }
    else
    {
        # The entry didn't contain any illegal chars, etc. so we proceed with adding it to the main list

        $covidList.Add($entryMain)
        foreach ($p in $prefixList)
        {
            $covidList.Add($($p+$entryMain))
        }
    }
}

Write-Host -ForegroundColor Green "Completed building domain list"

# Delete old list
[System.IO.File]::Delete($outputFullPath)

foreach ($cl in $covidList)
{
    #echo $cl >> $outputFullPath
    Write-Output -InputObject $cl | Out-File -FilePath $outputFullPath -Append
}

Write-Host -ForegroundColor Green "Wrote LR list text file to: ${outputFullPath}"
Write-Host -ForegroundColor Green "Done!"