# Smoke test for Windows PowerShell
# Starts the server, hits real HTTP endpoints, tears down.
#
# Usage (from project root):
#     .\tests\smoke_test.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

# Use a separate test DB
$env:THREAT_MODELER_DB = "$env:TEMP\smoke_test_$PID.db"
$env:JWT_SECRET = "smoke-test-secret-do-not-use-dGVzdA=="
$env:INITIAL_ADMIN_EMAIL = "admin@smoke.test"
$env:INITIAL_ADMIN_PASSWORD = "SmokePass123!"
$env:PORT = "8765"
$env:HOST_ADDR = "127.0.0.1"
$env:HOST = "127.0.0.1"

# Cleanup old DB if present
if (Test-Path $env:THREAT_MODELER_DB) {
    Remove-Item $env:THREAT_MODELER_DB -Force
}

$Base = "http://127.0.0.1:8765"
$Pass = 0
$Fail = 0

function Check {
    param([string]$Name, [scriptblock]$Block)
    try {
        & $Block
        $script:Pass++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:Fail++
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        Write-Host "         $_" -ForegroundColor Yellow
    }
}

Write-Host "`nStarting server on :8765..." -ForegroundColor Cyan
$serverProc = Start-Process -FilePath "python" -ArgumentList "app.py" `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$env:TEMP\smoke_server.log" `
    -RedirectStandardError "$env:TEMP\smoke_server_err.log"

# Cleanup at the end no matter what
try {
    # Wait for server up
    $up = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $r = Invoke-RestMethod -Uri "$Base/api/health" -Method Get -TimeoutSec 2
            if ($r.status -eq "ok") { $up = $true; break }
        } catch { }
    }
    if (-not $up) {
        Write-Host "  Server failed to start. Check $env:TEMP\smoke_server.log" -ForegroundColor Red
        Get-Content "$env:TEMP\smoke_server.log" -Tail 30
        exit 1
    }
    Write-Host "  Server is up" -ForegroundColor Green

    Write-Host "`n=== Health & auth ===" -ForegroundColor Cyan

    Check "GET /api/health is public" {
        $r = Invoke-RestMethod -Uri "$Base/api/health" -Method Get
        if ($r.status -ne "ok") { throw "expected status=ok" }
    }

    $loginBody = @{
        email = $env:INITIAL_ADMIN_EMAIL
        password = $env:INITIAL_ADMIN_PASSWORD
    } | ConvertTo-Json
    $loginResp = Invoke-RestMethod -Uri "$Base/api/auth/login" `
        -Method Post -Body $loginBody -ContentType "application/json"
    $adminToken = $loginResp.access_token

    Check "Admin login succeeds" {
        if (-not $adminToken) { throw "no access token returned" }
    }

    Check "GET /api/auth/me returns user + permissions" {
        $r = Invoke-RestMethod -Uri "$Base/api/auth/me" `
            -Headers @{Authorization = "Bearer $adminToken"}
        if ($r.user.email -ne $env:INITIAL_ADMIN_EMAIL) { throw "wrong email" }
        if (-not ($r.permissions -contains "audit.read")) { throw "missing audit.read" }
    }

    Check "Endpoints require auth (401 without token)" {
        try {
            Invoke-RestMethod -Uri "$Base/api/users" -Method Get
            throw "should have failed"
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -ne 401) {
                throw "expected 401, got $($_.Exception.Response.StatusCode.value__)"
            }
        }
    }

    Write-Host "`n=== RBAC ===" -ForegroundColor Cyan

    # Create a release
    $relBody = @{name="Smoke Release"; description="test"} | ConvertTo-Json
    $rel = Invoke-RestMethod -Uri "$Base/api/releases" -Method Post `
        -Headers @{Authorization = "Bearer $adminToken"} `
        -Body $relBody -ContentType "application/json"
    $relId = $rel.id

    Check "Admin can create release" { if (-not $relId) { throw "no id returned" } }

    # Create a feature
    $featBody = @{release_id=$relId; name="Smoke Feature"; description=""} | ConvertTo-Json
    $feat = Invoke-RestMethod -Uri "$Base/api/features" -Method Post `
        -Headers @{Authorization = "Bearer $adminToken"} `
        -Body $featBody -ContentType "application/json"
    $featId = $feat.id

    Check "Admin can create feature" { if (-not $featId) { throw "no id returned" } }

    # Self-register Alice (regular user)
    $regBody = @{
        email = "alice@smoke.test"
        password = "AlicePass123!"
        full_name = "Alice"
    } | ConvertTo-Json
    $alice = Invoke-RestMethod -Uri "$Base/api/auth/register" -Method Post `
        -Body $regBody -ContentType "application/json"
    $aliceToken = $alice.access_token
    $aliceId = $alice.user.id

    Check "User self-registration works" {
        if (-not $aliceToken) { throw "no token" }
        if ($alice.user.role -ne "user") { throw "wrong role: $($alice.user.role)" }
    }

    Check "User cannot create release (403)" {
        try {
            Invoke-RestMethod -Uri "$Base/api/releases" -Method Post `
                -Headers @{Authorization = "Bearer $aliceToken"} `
                -Body $relBody -ContentType "application/json"
            throw "should have failed"
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -ne 403) {
                throw "expected 403, got $($_.Exception.Response.StatusCode.value__)"
            }
        }
    }

    Check "User cannot list users (403)" {
        try {
            Invoke-RestMethod -Uri "$Base/api/users" -Method Get `
                -Headers @{Authorization = "Bearer $aliceToken"}
            throw "should have failed"
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -ne 403) {
                throw "expected 403"
            }
        }
    }

    Check "User cannot read audit log (403)" {
        try {
            Invoke-RestMethod -Uri "$Base/api/audit-log" -Method Get `
                -Headers @{Authorization = "Bearer $aliceToken"}
            throw "should have failed"
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -ne 403) {
                throw "expected 403"
            }
        }
    }

    Write-Host "`n=== Visibility & ownership ===" -ForegroundColor Cyan

    # Grant Alice access to the feature
    $grantBody = @{feature_ids=@($featId)} | ConvertTo-Json
    Invoke-RestMethod -Uri "$Base/api/users/$aliceId/feature-access" -Method Put `
        -Headers @{Authorization = "Bearer $adminToken"} `
        -Body $grantBody -ContentType "application/json" | Out-Null

    # Alice creates a TM
    $sysJson = @{
        name="Demo"
        components=@(
            @{id="c1"; name="User"; type="external_entity"}
            @{id="c2"; name="Web"; type="webapp"}
        )
        data_flows=@(
            @{id="f1"; from="c1"; to="c2"; data="creds"; encrypted=$false; auth="none"}
        )
        trust_boundaries=@()
    }
    $tmBody = @{
        feature_id=$featId
        name="Alice TM"
        description=""
        system=$sysJson
        methodologies=@("stride")
    } | ConvertTo-Json -Depth 6
    $tm = Invoke-RestMethod -Uri "$Base/api/threat-models" -Method Post `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -Body $tmBody -ContentType "application/json"
    $tmId = $tm.id

    Check "User creates threat model in granted feature" {
        if (-not $tmId) { throw "no tm id" }
        if ($tm.owner_id -ne $aliceId) { throw "wrong owner" }
    }

    # Register Bob — no feature access — try to read Alice's TM (should 404)
    $bobReg = @{email="bob@smoke.test"; password="BobPass123!"; full_name="Bob"} | ConvertTo-Json
    $bob = Invoke-RestMethod -Uri "$Base/api/auth/register" -Method Post `
        -Body $bobReg -ContentType "application/json"
    $bobToken = $bob.access_token

    Check "Bob gets 404 (not 403) on Alice's TM — hides existence" {
        try {
            Invoke-RestMethod -Uri "$Base/api/threat-models/$tmId" -Method Get `
                -Headers @{Authorization = "Bearer $bobToken"}
            throw "should have failed"
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -ne 404) {
                throw "expected 404, got $($_.Exception.Response.StatusCode.value__)"
            }
        }
    }

    Check "Bob's threat-model list is empty" {
        $r = Invoke-RestMethod -Uri "$Base/api/threat-models" -Method Get `
            -Headers @{Authorization = "Bearer $bobToken"}
        if ($r.Count -ne 0) { throw "expected 0, got $($r.Count)" }
    }

    Write-Host "`n=== Analyze + report ===" -ForegroundColor Cyan

    $analyzeBody = @{methodologies=@("stride")} | ConvertTo-Json
    $analysis = Invoke-RestMethod -Uri "$Base/api/threat-models/$tmId/analyze" -Method Post `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -Body $analyzeBody -ContentType "application/json"

    Check "Analysis runs and returns threats" {
        if ($analysis.summary.total -lt 1) { throw "no threats found" }
    }

    Check "Markdown report contains inline SVG (DFD)" {
        $reportText = Invoke-RestMethod -Uri "$Base/api/threat-models/$tmId/report/markdown" `
            -Method Get -Headers @{Authorization = "Bearer $aliceToken"}
        if ($reportText -notmatch "<svg") { throw "DFD missing in report" }
        if ($reportText -notmatch "Trust Boundaries") { throw "Trust boundaries section missing" }
    }

    Check "PDF report generates" {
        $pdfPath = "$env:TEMP\smoke_report.pdf"
        Invoke-WebRequest -Uri "$Base/api/threat-models/$tmId/report/pdf" `
            -Headers @{Authorization = "Bearer $aliceToken"} `
            -OutFile $pdfPath
        if ((Get-Item $pdfPath).Length -lt 1000) { throw "PDF too small" }
        Remove-Item $pdfPath -Force
    }

    Write-Host "`n=== Self-mod protection & audit ===" -ForegroundColor Cyan

    Check "Admin cannot demote self (400)" {
        $me = Invoke-RestMethod -Uri "$Base/api/auth/me" `
            -Headers @{Authorization = "Bearer $adminToken"}
        $myId = $me.user.id
        try {
            Invoke-RestMethod -Uri "$Base/api/users/$myId/role" -Method Put `
                -Headers @{Authorization = "Bearer $adminToken"} `
                -Body (@{role="user"} | ConvertTo-Json) -ContentType "application/json"
            throw "should have failed"
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -ne 400) { throw "expected 400" }
        }
    }

    Check "Audit log captures activity" {
        $logs = Invoke-RestMethod -Uri "$Base/api/audit-log?limit=200" `
            -Headers @{Authorization = "Bearer $adminToken"}
        if ($logs.Count -lt 5) { throw "too few audit entries: $($logs.Count)" }
        $denyLogins = $logs | Where-Object { $_.action -eq "user.login" -and $_.decision -eq "deny" }
        # Should have at least the "wrong password" deny we never made — but register/login grants exist
        if (($logs | Where-Object { $_.action -eq "user.register" }).Count -lt 2) {
            throw "register events missing"
        }
    }
}
finally {
    Write-Host "`nStopping server (PID=$($serverProc.Id))..." -ForegroundColor Cyan
    Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    if (Test-Path $env:THREAT_MODELER_DB) {
        Remove-Item $env:THREAT_MODELER_DB -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host ("=" * 60)
if ($Fail -eq 0) {
    Write-Host "  ALL $Pass SMOKE TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "  $Pass passed, $Fail FAILED" -ForegroundColor Red
}
Write-Host ("=" * 60)

exit $Fail
