<#
.SYNOPSIS
Produces a multi-tab Excel workbook containing summary and details of AppLocker events to support advanced analysis.

.DESCRIPTION
Converts output from the Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1 scripts to a multi-tab Excel workbook supporting numerous views of the data, many including graphs.
Worksheets include:
* Summary tab showing date/time ranges of the reported events and other summary information.
* Numbers of distinct users running files from each high-level location such as user profile, hot/removable, non-default root directories, etc.
* Numbers of distinct users running files from each observed publisher.
* Numbers of distinct users running each observed file (by GenericPath).
* All combinations of publishers/products for signed files in events.
* All combinations of publishers/products and generic file paths ("generic" meaning that user-specific paths are replaced with %LOCALAPPDATA%, %USERPROFILE%, etc., as appropriate).
* Paths of unsigned files, with filename alone, file type, and file hash.
* Files and publishers grouped by user.
* Full details from Get-AppLockerEvents.ps1.
With the -RawEventCounts switch, the workbook adds sheets showing raw event counts for each machine, publisher, and user.
These separate tabs enable quick determination of the files running afoul of AppLocker rules and help quickly determine whether/how to adjust the rules.

.PARAMETER AppLockerEventsCsvFile
Optional path to CSV file produced by Get-AppLockerEvents.ps1 or Save-WEFEvents.ps1.
If not specified, this script invokes Get-AppLockerEvents.ps1 on the local computer and processes its output.

.PARAMETER SaveWorkbook
If AppLockerEventsCsvFile is specified and this option is set, the script saves the workbook to the same directory
as the input file and with the same file name but with the default Excel file extension.

.PARAMETER RawEventCounts
If the -RawEventCounts switch is specified, workbook includes additional worksheets focused on raw event counts per machine, per user, and per publisher.

.PARAMETER VirusTotalLookup
If the -VirusTotalLookup switch is specified, the script queries VirusTotal API for SHA256 hashes found in unsigned files and adds VirusTotal threat intelligence data to the "Unsigned file info" worksheet.

.PARAMETER VirusTotalApiKey
VirusTotal API key required when using -VirusTotalLookup. If not provided, the script will prompt for it.
You can get a free API key from https://www.virustotal.com/gui/join-us
Free tier allows 4 requests per minute; the script automatically handles rate limiting.
#>

[CmdletBinding(DefaultParameterSetName="GenerateTempCsv")]
param(
    # Path to CSV file produced by Get-AppLockerEvents.ps1
    [parameter(ParameterSetName="NamedCsvFile", Mandatory=$true)]
    [String]
    $AppLockerEventsCsvFile, 

    [parameter(ParameterSetName="NamedCsvFile")]
    [switch]
    $SaveWorkbook,

    [switch]
    $RawEventCounts,

    [switch]
    $VirusTotalLookup,

    [parameter(Mandatory=$false)]
    [String]
    $VirusTotalApiKey
)

$rootDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
# Get configuration settings and global functions from .\Support\Config.ps1)
# Dot-source the config file. Contains Excel-generation scripts.
. $rootDir\Support\Config.ps1

# Function to normalize hash (remove 0x prefix, uppercase, validate)
function Normalize-Hash {
    param([string]$hash)
    
    if ([string]::IsNullOrWhiteSpace($hash))
    {
        return $null
    }
    
    $hash = $hash.Trim()
    
    # Remove "0x" prefix if present
    if ($hash.StartsWith("0x", [System.StringComparison]::InvariantCultureIgnoreCase))
    {
        $hash = $hash.Substring(2)
    }
    
    # Remove any whitespace
    $hash = $hash -replace '\s', ''
    
    # Validate it's a hex string of correct length (SHA256 = 64 hex chars)
    if ($hash.Length -eq 64 -and $hash -match '^[0-9A-Fa-f]+$')
    {
        return $hash.ToUpper()
    }
    
    return $null
}

# Function to query VirusTotal API v2
function Get-VirusTotalReport {
    param(
        [string]$hash,
        [string]$apiKey
    )
    
    $hash = Normalize-Hash -hash $hash
    if ($null -eq $hash)
    {
        return @{
            Status = "Invalid"
            Detections = 0
            TotalScans = 0
            ScanDate = ""
            Permalink = ""
            Error = "Invalid hash format"
        }
    }
    
    # Use v2 API (widely compatible, still supported)
    # v2 API uses apikey and resource as query parameters for GET requests
    $uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$hash"
    
    try
    {
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
        
        if ($response.response_code -eq 1)
        {
            # Hash found in VirusTotal
            return @{
                Status = "Found"
                Detections = $response.positives
                TotalScans = $response.total
                ScanDate = if ($response.scan_date) { $response.scan_date } else { "" }
                Permalink = if ($response.permalink) { $response.permalink } else { "" }
                Error = ""
            }
        }
        elseif ($response.response_code -eq 0)
        {
            # Hash not found in VirusTotal
            return @{
                Status = "Not Found"
                Detections = 0
                TotalScans = 0
                ScanDate = ""
                Permalink = ""
                Error = ""
            }
        }
        else
        {
            return @{
                Status = "Error"
                Detections = 0
                TotalScans = 0
                ScanDate = ""
                Permalink = ""
                Error = "Unknown response code: $($response.response_code)"
            }
        }
    }
    catch
    {
        $errorMsg = $_.Exception.Message
        if ($_.Exception.Response)
        {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $errorMsg = "HTTP $statusCode : $errorMsg"
            
            # Handle rate limiting
            if ($statusCode -eq 204)
            {
                $errorMsg = "Rate limit exceeded. Please increase delay."
            }
            elseif ($statusCode -eq 403)
            {
                $errorMsg = "API key invalid or insufficient privileges."
            }
        }
        
        return @{
            Status = "Error"
            Detections = 0
            TotalScans = 0
            ScanDate = ""
            Permalink = ""
            Error = $errorMsg
        }
    }
}

$OutputEncodingPrevious = $OutputEncoding
$OutputEncoding = [System.Text.ASCIIEncoding]::Unicode

$tempfile = [string]::Empty

if ($AppLockerEventsCsvFile)
{
    if (!(Test-Path($AppLockerEventsCsvFile)))
    {
        Write-Warning "File not found: $AppLockerEventsCsvFile"
        return
    }

    # Get absolute path to input file. (Note that [System.IO.Path]::GetFullName doesn't do this...)
    $AppLockerEventsCsvFileFullPath = $AppLockerEventsCsvFile
    if (!([System.IO.Path]::IsPathRooted($AppLockerEventsCsvFile)))
    {
        $AppLockerEventsCsvFileFullPath = [System.IO.Path]::Combine((Get-Location).Path, $AppLockerEventsCsvFile)
    }
    $dataSourceName = [System.IO.Path]::GetFileName($AppLockerEventsCsvFile)
}
else
{
    $tempfile = [System.IO.Path]::GetTempFileName()
    $AppLockerEventsCsvFileFullPath = $AppLockerEventsCsvFile = $tempfile
    $dataSourceName = "(Get-AppLockerEvents.ps1 output)"
    & $rootDir\Get-AppLockerEvents.ps1 | Out-File $tempfile -Encoding unicode
}


Write-Host "Reading data from $AppLockerEventsCsvFile" -ForegroundColor Cyan
$csvFull = @(Get-Content $AppLockerEventsCsvFile)
$dataUnfiltered = @($csvFull | ConvertFrom-Csv -Delimiter "`t")
$dataFiltered   = @($dataUnfiltered | Where-Object { $_.EventType -ne $sFiltered })
$eventsSigned   = @($dataFiltered | Where-Object { $_.PublisherName -ne $sUnsigned -and $_.PublisherName -ne $sNoPublisher })
$eventsUnsigned = @($dataFiltered | Where-Object { $_.PublisherName -eq $sUnsigned -or  $_.PublisherName -eq $sNoPublisher })

if ($dataUnfiltered.Length -eq 0)
{
    Write-Warning "No data. Exiting."
    return
}

$nEvents = $dataFiltered.Length
$nSignedEvents = $eventsSigned.Length
$nUnsignedEvents = $eventsUnsigned.Length

if (CreateExcelApplication)
{
    # Array to set sort order descending on Count and then ascending on Name
    $CountDescNameAsc = @( @{ Expression = "Count"; Descending = $true }, @{ Expression = "Name"; Descending = $false} )

    # Lines of text for the summary page
    $tabname = "Summary"
    Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
    [System.Collections.ArrayList]$text = @()
    $text.Add( "Summary information" ) | Out-Null
    $text.Add( "" ) | Out-Null
    $text.Add( "Data source:`t" + $dataSourceName ) | Out-Null
    if ($nEvents -gt 0)
    {
        $dtsort = ($dataFiltered.EventTime | Sort-Object); 
        $dtFirst = ([datetime]($dtsort[0])).ToString()
        $dtLast =  ([datetime]($dtsort[$dtsort.Length - 1])).ToString()
    }
    else
    {
        $dtFirst = $dtLast = "N/A"
    }
    $text.Add( "First event:`t" + $dtFirst ) | Out-Null
    $text.Add( "Last event:`t" + $dtLast ) | Out-Null
    $text.Add( "" ) | Out-Null
    $text.Add( "Number of events:`t" + $nEvents.ToString() ) | Out-Null
    $text.Add( "Number of signed-file events:`t" + $nSignedEvents.ToString() ) | Out-Null
    $text.Add( "Number of unsigned-file events:`t" + $nUnsignedEvents.ToString() ) | Out-Null
    # Make sure the result of the pipe is an array, even if only one item.
    $text.Add( "Number of machines reporting events:`t" + ( @($dataUnfiltered.MachineName | Group-Object)).Count.ToString() ) | Out-Null
    $text.Add( "Number of users reporting events:`t" + ( @($dataFiltered.UserName | Group-Object)).Count.ToString() ) | Out-Null
    AddWorksheetFromText -text $text -tabname $tabname

    if ($nEvents -gt 0)
    {
        # Users per location:
        $tabname = "# Users per Location"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object Location, UserName -Unique | Group-Object Location | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        # Change the headers
        $csv[0] = "Location" + "`t" + "# of distinct users"
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
    }

    if ($nEvents -gt 0)
    {
        # Users per publisher:
        $tabname = "# Users per Publisher"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object PublisherName, UserName -Unique | Group-Object PublisherName | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        # Change the headers
        $csv[0] = "PublisherName" + "`t" + "# of distinct users"
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
    }

    if ($nSignedEvents -gt 0)
    {
        # Publisher/product combinations:
        $tabname = "Publisher-product combinations"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($eventsSigned | Select-Object PublisherName, ProductName | Sort-Object PublisherName, ProductName -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    if ($nEvents -gt 0)
    {
        # Users per file:
        $tabname = "# Users per File"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object Location, GenericPath, UserName -Unique | Group-Object Location, GenericPath | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        # Change the headers
        $csv[0] = "Location, GenericPath" + "`t" + "# of distinct users"
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
    }

    if ($nSignedEvents -gt 0)
    {
        # Publisher/product/file combinations:
        $tabname = "Signed file info"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($eventsSigned | Select-Object PublisherName, ProductName, Location, GenericPath, FileName, FileType | Sort-Object PublisherName, ProductName, Location, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    if ($nUnsignedEvents -gt 0)
    {
        # Analysis of unsigned files:
        $tabname = "Unsigned file info"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        
        if ($VirusTotalLookup)
        {
            # Get API key if not provided
            if ([string]::IsNullOrEmpty($VirusTotalApiKey))
            {
                $secureKey = Read-Host "Enter VirusTotal API Key" -AsSecureString
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
                $VirusTotalApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
            
            if ([string]::IsNullOrEmpty($VirusTotalApiKey))
            {
                Write-Warning "VirusTotal API key is required for -VirusTotalLookup. Skipping VirusTotal lookup."
                $VirusTotalLookup = $false
            }
            else
            {
                Write-Host "Querying VirusTotal for unsigned file hashes..." -ForegroundColor Cyan
                
                # Get unique hashes from unsigned events
                $uniqueHashes = @{}
                $hashToEvents = @{}
                foreach ($event in $eventsUnsigned)
                {
                    if ($event.Hash -and $event.Hash -ne "(not reported)")
                    {
                        $normalized = Normalize-Hash -hash $event.Hash
                        if ($null -ne $normalized -and !$uniqueHashes.ContainsKey($normalized))
                        {
                            $uniqueHashes[$normalized] = $true
                            $hashToEvents[$normalized] = @()
                        }
                        if ($null -ne $normalized)
                        {
                            $hashToEvents[$normalized] += $event
                        }
                    }
                }
                
                Write-Host "Found $($uniqueHashes.Count) unique hashes to query. This may take a while due to rate limiting..." -ForegroundColor Cyan
                
                # Query VirusTotal for each unique hash
                $vtResults = @{}
                $queryCount = 0
                $totalQueries = $uniqueHashes.Count
                $delaySeconds = 15  # Free tier allows 4 requests per minute
                
                foreach ($hash in $uniqueHashes.Keys)
                {
                    $queryCount++
                    Write-Progress -Activity "Querying VirusTotal" -Status "Query $queryCount of $totalQueries" -PercentComplete (($queryCount / $totalQueries) * 100)
                    
                    Write-Host "[$queryCount/$totalQueries] Querying hash: $hash" -ForegroundColor Cyan
                    $result = Get-VirusTotalReport -hash $hash -apiKey $VirusTotalApiKey
                    $vtResults[$hash] = $result
                    
                    # Rate limiting: wait between requests (except for last one)
                    if ($queryCount -lt $totalQueries)
                    {
                        Start-Sleep -Seconds $delaySeconds
                    }
                }
                
                Write-Progress -Activity "Querying VirusTotal" -Completed
                
                # Merge VirusTotal results into events
                $eventsUnsignedWithVT = @()
                foreach ($event in $eventsUnsigned)
                {
                    $normalized = Normalize-Hash -hash $event.Hash
                    if ($null -ne $normalized -and $vtResults.ContainsKey($normalized))
                    {
                        $vtResult = $vtResults[$normalized]
                        $eventsUnsignedWithVT += [PSCustomObject]@{
                            Location = $event.Location
                            GenericPath = $event.GenericPath
                            FileName = $event.FileName
                            FileType = $event.FileType
                            Hash = $event.Hash
                            VT_Status = $vtResult.Status
                            VT_Detections = $vtResult.Detections
                            VT_TotalScans = $vtResult.TotalScans
                            VT_ScanDate = $vtResult.ScanDate
                            VT_Permalink = $vtResult.Permalink
                            VT_Error = $vtResult.Error
                        }
                    }
                    else
                    {
                        # Event with invalid or missing hash
                        $eventsUnsignedWithVT += [PSCustomObject]@{
                            Location = $event.Location
                            GenericPath = $event.GenericPath
                            FileName = $event.FileName
                            FileType = $event.FileType
                            Hash = $event.Hash
                            VT_Status = if ($null -eq $normalized) { "Invalid Hash" } else { "Not Queried" }
                            VT_Detections = ""
                            VT_TotalScans = ""
                            VT_ScanDate = ""
                            VT_Permalink = ""
                            VT_Error = if ($null -eq $normalized) { "Invalid or missing hash" } else { "" }
                        }
                    }
                }
                
                # Create CSV with VirusTotal columns
                # Group by Location and GenericPath to get unique combinations, taking first occurrence of each
                $uniqueEvents = $eventsUnsignedWithVT | Group-Object -Property Location, GenericPath | ForEach-Object { $_.Group[0] }
                $csv = @($uniqueEvents | Sort-Object Location, GenericPath | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
                AddWorksheetFromCsvData -csv $csv -tabname $tabname
                
                # Summary
                $foundCount = ($vtResults.Values | Where-Object { $_.Status -eq "Found" }).Count
                $detectedCount = ($vtResults.Values | Where-Object { $_.Status -eq "Found" -and $_.Detections -gt 0 }).Count
                Write-Host "VirusTotal lookup complete: $foundCount hashes found, $detectedCount with detections" -ForegroundColor $(if ($detectedCount -gt 0) { "Yellow" } else { "Green" })
            }
        }
        
        if (!$VirusTotalLookup)
        {
            # Standard unsigned file info without VirusTotal
            $csv = @($eventsUnsigned | Select-Object Location, GenericPath, FileName, FileType, Hash | Sort-Object Location, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
            AddWorksheetFromCsvData -csv $csv -tabname $tabname
        }
    }

    if ($nEvents -gt 0)
    {
        # Files by user
        $tabname = "Files by User"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object UserName, Location, GenericPath, FileType, PublisherName, ProductName | Sort-Object UserName, Location, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    if ($nEvents -gt 0)
    {
        # Files by user (details)
        $tabname = "Files by User (details)"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered | Select-Object UserName, MachineName, EventTimeXL, FileType, GenericPath, PublisherName, ProductName | Sort-Object UserName, MachineName, EventTimeXL, FileType, GenericPath -Unique | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        AddWorksheetFromCsvData -csv $csv -tabname $tabname
    }

    # All event data
    AddWorksheetFromCsvFile -filename $AppLockerEventsCsvFileFullPath -tabname "Full details"

    if ($RawEventCounts)
    {
        # Events per machine:
        $tabname = "# Events per Machine"
        Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
        $csv = @($dataFiltered.MachineName | Group-Object | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
        if ($csv.Length -eq 0) { $csv = @("header") } # No events - insert dummy header row, replaced in a moment
        $csv += @($dataUnfiltered | Where-Object { $_.EventType -eq $sFiltered } | ForEach-Object { $_.MachineName + "`t0" })
        # Change the headers
        if ($csv.Length -gt 0 ) { $csv[0] = "MachineName" + "`t" + "Event count" }
        AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart

        if ($nEvents -gt 0)
        {
            # Counts of each publisher:
            $tabname = "# Events per Publisher"
            Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
            $csv = @($dataFiltered.PublisherName | Group-Object | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
            # Change the headers
            if ($csv.Length -gt 0 ) { $csv[0] = "PublisherName" + "`t" + "Events" }
            AddWorksheetFromCsvData -csv $csv -tabname $tabname -AddChart
        }

        if ($nEvents -gt 0)
        {
            # Events per user:
            $tabname = "# Events per User"
            Write-Host "Gathering data for `"$tabname`"..." -ForegroundColor Cyan
            $csv = @($dataFiltered.UserName | Group-Object | Select-Object Name, Count | Sort-Object -Property $CountDescNameAsc | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation)
            # Change the headers
            $csv[0] = "UserName" + "`t" + "Events"
            AddWorksheetFromCsvData -csv $csv -tabname $tabname -CrLfEncoded "" -AddChart
        }
    }

    SelectFirstWorksheet

    if ($SaveWorkbook)
    {
        $xlFname = [System.IO.Path]::ChangeExtension($AppLockerEventsCsvFileFullPath, ".xlsx")
        SaveWorkbook -filename $xlFname
    }

    ReleaseExcelApplication
}

if ($tempfile.Length -gt 0)
{
    Remove-Item $tempfile
}

$OutputEncoding = $OutputEncodingPrevious


