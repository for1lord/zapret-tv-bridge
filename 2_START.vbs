' Zapret TV & Mobile Bridge — Silent Background Launcher
Option Explicit

Dim fso, shell, curDir, pywExe, testPath, subFolder

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
curDir = fso.GetParentFolderName(WScript.ScriptFullName)

pywExe = ""

' 1. Check PATH for pythonw.exe
On Error Resume Next
Dim execPath
execPath = shell.Exec("where pythonw.exe").StdOut.ReadLine()
If fso.FileExists(execPath) Then
    pywExe = execPath
End If
On Error GoTo 0

' 2. Search LocalAppData\Programs\Python
If pywExe = "" Then
    Dim localApp, pyFolder
    localApp = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python"
    If fso.FolderExists(localApp) Then
        For Each subFolder In fso.GetFolder(localApp).SubFolders
            testPath = subFolder.Path & "\pythonw.exe"
            If fso.FileExists(testPath) Then
                pywExe = testPath
                Exit For
            End If
        Next
    End If
End If

' 3. Search ProgramFiles\Python
If pywExe = "" Then
    Dim progFiles
    progFiles = shell.ExpandEnvironmentStrings("%ProgramFiles%")
    If fso.FolderExists(progFiles) Then
        For Each subFolder In fso.GetFolder(progFiles).SubFolders
            If InStr(1, subFolder.Name, "Python", vbTextCompare) = 1 Then
                testPath = subFolder.Path & "\pythonw.exe"
                If fso.FileExists(testPath) Then
                    pywExe = testPath
                    Exit For
                End If
            End If
        Next
    End If
End If

' 4. Fallback to generic pythonw or python
If pywExe = "" Then pywExe = "pythonw.exe"

' Launch silently without any console window (WindowStyle = 0)
shell.CurrentDirectory = curDir
shell.Run """" & pywExe & """ """ & curDir & "\zapret_tv_bridge.py"" --daemon", 0, False
