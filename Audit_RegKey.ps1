function Audit_RegKey{
    Param(

        [Parameter(Mandatory=$true)]
    
        [string]$Path

        )

    $valid= get-item -path $path -ErrorAction SilentlyContinue

    if (!$valid){
        Write-Host "[ERROR] Invalid Registry Path." -ForegroundColor Red
    }

    if ($valid){    
        $RegKey_ACL = Get-Acl $path
        $AccessRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone","SetValue,CreateSubKey,Delete”,"none","none",”Success")
        $RegKey_ACL.AddAuditRule($AccessRule)
        $RegKey_ACL | Set-Acl $path
        write-output "$path"
        Write-Output "OK."
    }
}