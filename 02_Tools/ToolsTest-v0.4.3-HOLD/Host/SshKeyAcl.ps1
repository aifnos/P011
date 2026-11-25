# Changes only the DACL of the dedicated project private key, not its SACL/owner.
# Native functions are documented in Microsoft Learn. No privilege is enabled.
function Initialize-P011KeyAcl {
    if ('P011PrivateKeyDaclV043' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class P011PrivateKeyDaclV043 {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks;
        public uint FileIndexHigh, FileIndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,
        [MarshalAs(UnmanagedType.Bool)] out bool present, out IntPtr dacl,
        [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int kind, uint info,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(SafeFileHandle handle, int kind, uint info,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    private static RawSecurityDescriptor ReadOwnerAndDacl(SafeFileHandle handle) {
        IntPtr owner, group, dacl, sacl, sd;
        uint error = GetSecurityInfo(handle, 1, 0x00000005U,
            out owner, out group, out dacl, out sacl, out sd);
        if (error != 0) throw new Win32Exception((int)error, "Read dedicated-key owner/DACL failed");
        try {
            uint size = GetSecurityDescriptorLength(sd);
            if (size < 20 || size > 1048576) throw new IOException("Invalid security descriptor size");
            byte[] bytes = new byte[(int)size];
            Marshal.Copy(sd, bytes, 0, bytes.Length);
            return new RawSecurityDescriptor(bytes, 0);
        } finally { if (sd != IntPtr.Zero) LocalFree(sd); }
    }
    public static string Restrict(string path) {
        string full = Path.GetFullPath(path);
        if (!String.Equals(Path.GetFileName(full), "p011-tools-client-ed25519", StringComparison.Ordinal))
            throw new IOException("Only the dedicated project private key is permitted");
        string item = full;
        while (!String.IsNullOrEmpty(item)) {
            FileAttributes a = File.GetAttributes(item);
            if ((a & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Refusing reparse points in dedicated-key path");
            string parent = Path.GetDirectoryName(item);
            if (parent == item) break;
            item = parent;
        }
        // READ_CONTROL | WRITE_DAC. No ACCESS_SYSTEM_SECURITY or WRITE_OWNER.
        using (SafeFileHandle handle = CreateFileW(full, 0x00060000U, 1, IntPtr.Zero, 3, 0x00200000U, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open dedicated key for DACL-only change failed");
            FileInformation fi;
            if (!GetFileInformationByHandle(handle, out fi)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((fi.Attributes & 0x410U) != 0 || fi.NumberOfLinks != 1 || fi.FileSizeHigh != 0 || fi.FileSizeLow > 65536)
                throw new IOException("Refusing directory, link or unexpected key file");
            SecurityIdentifier user;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) { user = identity.User; }
            if (user == null) throw new IOException("Current user SID is unavailable");
            RawSecurityDescriptor before = ReadOwnerAndDacl(handle);
            if (before.Owner == null || !(before.Owner.Equals(user) ||
                before.Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                before.Owner.IsWellKnown(WellKnownSidType.LocalSystemSid)))
                throw new IOException("Private key has an unexpected owner; owner was not changed");
            IntPtr sd = IntPtr.Zero;
            uint size;
            try {
                string sddl = "D:P(A;;FA;;;" + user.Value + ")";
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                bool present, defaulted; IntPtr dacl;
                if (!GetSecurityDescriptorDacl(sd, out present, out dacl, out defaulted) || !present || dacl == IntPtr.Zero)
                    throw new IOException("Refusing absent/null key DACL");
                // PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION only.
                uint error = SetSecurityInfo(handle, 1, 0x80000004U,
                    IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (error != 0) throw new Win32Exception((int)error, "DACL-only update failed");
            } finally { if (sd != IntPtr.Zero) LocalFree(sd); }
            RawSecurityDescriptor after = ReadOwnerAndDacl(handle);
            if (!before.Owner.Equals(after.Owner) || after.DiscretionaryAcl == null ||
                after.DiscretionaryAcl.Count != 1 ||
                (after.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
                throw new IOException("Key permission readback failed");
            CommonAce ace = after.DiscretionaryAcl[0] as CommonAce;
            if (ace == null || ace.AceQualifier != AceQualifier.AccessAllowed ||
                !ace.SecurityIdentifier.Equals(user) || ace.AccessMask != 0x001F01FF)
                throw new IOException("Key DACL does not exclusively grant the current user access");
            return "DACL_ONLY_VERIFIED: owner unchanged; SACL not requested; one current-user access rule";
        }
    }
}
'@
}

function Protect-P011PrivateKey {
    param([Parameter(Mandatory=$true)][string]$LiteralPath)
    Initialize-P011KeyAcl
    return [P011PrivateKeyDaclV043]::Restrict($LiteralPath)
}

function Test-P011PrivateKeyAcl {
    param([Parameter(Mandatory=$true)][string]$WorkRoot)
    $directory=Join-Path $WorkRoot ('tests\ssh-key-acl-'+[Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory)
    $file=Join-Path $directory 'p011-tools-client-ed25519'
    try {
        [IO.File]::WriteAllText($file,'P011 disposable ACL fixture; this is NOT a key.')
        $status=Protect-P011PrivateKey -LiteralPath $file
        if($status -notlike 'DACL_ONLY_VERIFIED:*'){throw 'Dedicated key DACL self-test did not verify.'}
        return 'SSH_KEY_ACL_SELFTEST_OK: disposable host file only; no device I/O.'
    } finally {
        if(Test-Path -LiteralPath $directory){Remove-Item -LiteralPath $directory -Recurse -Force}
    }
}
