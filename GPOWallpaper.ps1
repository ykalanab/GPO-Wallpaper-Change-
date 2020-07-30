#----------------------------------------------------------------#
# GPO wallpaper Update 
# zone
#----------------------------------------------------------------#

#get remote connection 
$remotePc = "192.168.213.166"
#$Domanin = "CN=Computers,DC=zone,DC=com"
$cred=Get-Credential

#Get AD computers 
#$computers = Get-ADComputer -Filter * -SearchBase "CN=Computers,DC=testdomain,DC=local"
#$computers = Get-ADComputer -Filter * -SearchBase $Domanin

#Import-PSSession -Session $remotePc
$sess = New-PSSession -Credential $cred -ComputerName $remotePc

Enter-PSSession $sess
#remote machine hello message 
Invoke-Command -Session $sess -ScriptBlock {msg username 'This is a test message.'}

$Remote = Get-Content 'C:\TEST\PCLIST.TXT'

foreach ($sess in $Remote)
    {
        Invoke-Command -ComputerName $sess -ScriptBlock
        $CmdMessage = {C:\windows\system32\msg.exe * 'This is a test!'}
        $CmdMessage | Invoke-Expression
    }



#image share path
$IMAGES = Get-ChildItem -path  C:\Windows\WEB\Wallpaper\Windows\*.jpg -Recurse -Force
    
ForEach ($IMAGE in $IMAGES)
    {
#edit GPO registry###
     Set-GPRegistryValue -Name "wallpaper_change" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName 'WallpaperStyle' -Value 0 -Type Dword
     Set-GPregistryValue -Name "wallpaper_change" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName 'Wallpaper' -Value $IMAGES -Type ExpandString
    }

#gpo Update

Foreach ($c in ($computers.Name))
{
    &psexec \\$c -i gpupdate 
}
#Invoke-GPUpdate

Exit-PSSession
Remove-PSSession $sess

