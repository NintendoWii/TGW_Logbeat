function Audit_RegKey($path){
$valid= get-item -path $path
    if ($valid){    
        $RegKey_ACL = Get-Acl $path
        $AccessRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone","SetValue,CreateSubKey,Delete”,"none","none",”Success")
        $RegKey_ACL.AddAuditRule($AccessRule)
        $RegKey_ACL | Set-Acl $path
        Write-Output "OK."
    }
}