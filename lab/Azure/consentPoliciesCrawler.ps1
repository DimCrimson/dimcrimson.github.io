param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId
)

try {
    # -----------------------------
    # Connect to Microsoft Graph
    # -----------------------------
    Connect-MgGraph `
        -TenantId $TenantId `
        -Scopes "Policy.Read.All","Directory.Read.All","Application.Read.All"

    # -----------------------------
    # Retrieve authorization policy
    # -----------------------------
    try {
        $auth = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $assignedPolicies = $auth.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve authorization policy"
        Write-Host "Reason: $($_.Exception.Message)"

        if ($_.Exception.Message -match "403|Forbidden|Insufficient privileges") {
            Write-Host "Likely cause: missing Policy.Read.All or admin consent in this tenant."
        }

        return
    }

    if (-not $assignedPolicies) {
        Write-Host "No permission grant policies are explicitly assigned (default behavior applies)."
        return
    }

    # -----------------------------
    # Resolve permission IDs into readable names
    # -----------------------------
    function Resolve-PermissionIds {
        param (
            [string]$resourceAppId,
            [array]$permissionIds
        )

        # Handle wildcard case ("any resource")
        if ($resourceAppId -eq "any") {
            return $permissionIds | ForEach-Object {
                "[any-resource] $_"
            }
        }

        try {
            $sp = Get-MgServicePrincipal -Filter "appId eq '$resourceAppId'" -ErrorAction Stop
        }
        catch {
            Write-Host "[WARN] Failed to resolve service principal: $resourceAppId"
            return $permissionIds
        }

        if (-not $sp) {
            return $permissionIds
        }

        $scopes = $sp.Oauth2PermissionScopes

        foreach ($id in $permissionIds) {
            $match = $scopes | Where-Object { $_.Id -eq $id }
            if ($match) { $match.Value } else { $id }
        }
    }

    # -----------------------------
    # Iterate through policies
    # -----------------------------
    foreach ($policyRef in $assignedPolicies) {

        $policyId = $policyRef.Split(".")[-1]

        Write-Host "`n==============================="
        Write-Host "Policy: $policyId"
        Write-Host "==============================="

        # -----------------------------
        # INCLUDED rules
        # -----------------------------
        Write-Host "`nIncluded permissions"

        try {
            $includes = Get-MgPolicyPermissionGrantPolicyInclude `
                -PermissionGrantPolicyId $policyId `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve INCLUDE rules for policy $policyId"
            Write-Host "Reason: $($_.Exception.Message)"

            if ($_.Exception.Message -match "403|Forbidden|Insufficient privileges") {
                Write-Host "Missing permission: Policy.Read.All"
            }

            continue
        }

        foreach ($inc in $includes) {

            Write-Host "`nResourceAppId: $($inc.ResourceApplication)"
            Write-Host "PermissionType: $($inc.PermissionType)"
            Write-Host "Classification: $($inc.PermissionClassification)"

            if ($inc.Permissions) {
                $resolved = Resolve-PermissionIds `
                    -resourceAppId $inc.ResourceApplication `
                    -permissionIds $inc.Permissions

                Write-Host "Permissions:"
                $resolved | ForEach-Object { Write-Host " - $_" }
            }
            else {
                Write-Host "Permissions: all matching classification"
            }
        }

        # -----------------------------
        # EXCLUDED rules
        # -----------------------------
        Write-Host "`nExcluded permissions"

        try {
            $excludes = Get-MgPolicyPermissionGrantPolicyExclude `
                -PermissionGrantPolicyId $policyId `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve EXCLUDE rules for policy $policyId"
            Write-Host "Reason: $($_.Exception.Message)"

            if ($_.Exception.Message -match "403|Forbidden|Insufficient privileges") {
                Write-Host "Likely missing Policy.Read.All or tenant blocks this endpoint."
            }

            continue
        }

        foreach ($exc in $excludes) {

            Write-Host "`nResourceAppId: $($exc.ResourceApplication)"
            Write-Host "PermissionType: $($exc.PermissionType)"

            if ($exc.Permissions) {
                $resolved = Resolve-PermissionIds `
                    -resourceAppId $exc.ResourceApplication `
                    -permissionIds $exc.Permissions

                Write-Host "Permissions:"
                $resolved | ForEach-Object { Write-Host " - $_" }
            }
            else {
                Write-Host "Permissions: all"
            }
        }
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
