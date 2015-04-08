$ModuleName = (Split-Path -leaf $MyInvocation.MyCommand.Path) -replace '\.[Tt][Ee][Ss][Tt][Ss].[Pp][Ss]1'
$TestsFolder = 1..4 |
    foreach {$Path = $MyInvocation.MyCommand.Path } {$Path = Split-Path $Path} {$Path}
$RootOfModule = Split-Path $TestsFolder
$CurrentResourceModulePath  = Join-Path $RootOfModule "DscResources/$ModuleName"

Import-Module $CurrentResourceModulePath

InModuleScope $ModuleName {
  describe 'Test-TargetResource' {
    $TargetResourceParams = @{
      Name = 'PesterTest'
      Path = 'c:\Pester'
      Ensure = 'Present'
    }
    context 'validates if the share exists'{
      it 'returns false when the share is not present' {
        mock Get-SmbShare -mockwith {Write-Error 'No such share.'}
        test-targetresource @TargetResourceParams | should be $false
      }
      it 'returns true when the share is present' {
        mock Get-SmbShare -mockwith {
          [pscustomobject]@{
            Name = 'PesterTest'
            Path = 'c:\Pester'
          }
        }
        mock Get-SmbShareAccess -mockwith {}
        test-targetresource @TargetResourceParams | should be $true
      }
    }
  }
}