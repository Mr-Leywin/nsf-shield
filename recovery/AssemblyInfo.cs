using System.Reflection;
using System.Runtime.Versioning;

// the version attributes come from build.ps1 (build\gen\RecoveryVersion.g.cs, the same version as NSFShield.exe)
[assembly: AssemblyTitle("NSF Shield proxy recovery")]                                  // FileDescription
[assembly: AssemblyDescription("Restores the Windows proxy setting that NSF Shield's ByeDPI engine changed, at the next sign-in")]
[assembly: AssemblyCompany("Nightshift (Osman Barış MEDİNE)")]                          // the same as App.Publisher (checked by the self-test)
[assembly: AssemblyProduct("NSF Shield")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Nightshift (Osman Barış MEDİNE)")]
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
