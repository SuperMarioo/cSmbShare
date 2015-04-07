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
      mock Get-SmbShare -mockwith {Write-Error 'No such share.'}
      it 'returns false when the share is not present' {
        test-targetresource @TargetResourceParams | should be $false
      }
    }
  }
}