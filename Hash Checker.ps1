<#
AUTHOR  : Duncan Jeffreys <jeffreysda@gmail.com>
LINK    : https://github.com/JeffreysDA

CREATED : 07/16/2021
UPDATED : 11/07/2021
VERSION : 1.0.0

COMMENTS: 
Detects that hashes of a given file and compares them against the provided hashes, then informs the user if the hash values match or not.
#>


<##################################################
                DEPENDANCIES
##################################################>

<#Adds the necessary assemblies to display a GUI#>
Add-Type -AssemblyName System.Drawing, System.Windows.Forms, PresentationCore, PresentationFramework


<##################################################
                VARIABLES
##################################################>

<#Import Config File#>


<#Script Scope Variables#>
$Script:ScriptName = 'File Hash Checker'

$Script:IndicatorMACTDES_T = $Null
$Script:IndicatorMACTDES_F = 'Black'
$Script:IndicatorMACTDES_B = 'Transparent'

$Script:IndicatorMD5_T = $Null
$Script:IndicatorMD5_F = 'Black'
$Script:IndicatorMD5_B = 'Transparent'

$Script:IndicatorRIPEMD160_T = $Null
$Script:IndicatorRIPEMD160_F = 'Black'
$Script:IndicatorRIPEMD160_B = 'Transparent'

$Script:IndicatorSHA1_T = $Null
$Script:IndicatorSHA1_F = 'Black'
$Script:IndicatorSHA1_B = 'Transparent'

$Script:IndicatorSHA256_T = $Null
$Script:IndicatorSHA256_F = 'Black'
$Script:IndicatorSHA256_B = 'Transparent'

$Script:IndicatorSHA384_T = $Null
$Script:IndicatorSHA384_F = 'Black'
$Script:IndicatorSHA384_B = 'Transparent'

$Script:IndicatorSHA512_T = $Null
$Script:IndicatorSHA512_F = 'Black'
$Script:IndicatorSHA512_B = 'Transparent'


<#Variables used for creation of Local Re-Activation Script#>



<#Config File Variables#>



<#Basic Variables#>



<##################################################
                SCRIPT FUNCTIONS
##################################################>


Function Refresh-Label {
  [CmdletBinding()]
  Param ([Parameter(Mandatory)]
         $Label,
         $NewText = $Null,
         $NewForeColor = $Null,
         $NewBackColor = $Null
        )

  If ($NewText -ne $Null) {
    $Label.Text = $NewText
  }
  If ($NewForeColor -ne $Null) {
    $Label.ForeColor = $NewForeColor
  }
  If ($NewBackColor -ne $Null) {
    $Label.BackColor = $NewBackColor
  }
}


Function Clear-GUI {
  $TextBox_FilePath.Clear()

  $TextBox_MACTDES.Clear()
  $TextBox_FileMACTDES.Clear()
  $Script:IndicatorMACTDES_T = ''
  $Script:IndicatorMACTDES_F = 'Black'
  $Script:IndicatorMACTDES_B = 'Transparent'

  $TextBox_MD5.Clear()
  $TextBox_FileMD5.Clear()
  $Script:IndicatorMD5_T = ''
  $Script:IndicatorMD5_F = 'Black'
  $Script:IndicatorMD5_B = 'Transparent'

  $TextBox_RIPEMD160.Clear()
  $TextBox_FileRIPEMD160.Clear()
  $Script:IndicatorRIPEMD160_T = ''
  $Script:IndicatorRIPEMD160_F = 'Black'
  $Script:IndicatorRIPEMD160_B = 'Transparent'

  $TextBox_SHA1.Clear()
  $TextBox_FileSHA1.Clear()
  $Script:IndicatorSHA1_T = ''
  $Script:IndicatorSHA1_F = 'Black'
  $Script:IndicatorSHA1_B = 'Transparent'

  $TextBox_SHA256.Clear()
  $TextBox_FileSHA256.Clear()
  $Script:IndicatorSHA256_T = ''
  $Script:IndicatorSHA256_F = 'Black'
  $Script:IndicatorSHA256_B = 'Transparent'

  $TextBox_SHA384.Clear()
  $TextBox_FileSHA384.Clear()
  $Script:IndicatorSHA384_T = ''
  $Script:IndicatorSHA384_F = 'Black'
  $Script:IndicatorSHA256_B = 'Transparent'

  $TextBox_SHA512.Clear()
  $TextBox_FileSHA512.Clear()
  $Script:IndicatorSHA512_T = ''
  $Script:IndicatorSHA512_F = 'Black'
  $Script:IndicatorSHA512_B = 'Transparent'

  Refresh-Label -Label $Indicator_MACTDES -NewText $Script:IndicatorMACTDES_T -NewForeColor $Script:IndicatorMACTDES_F -NewBackColor $Script:IndicatorMACTDES_B
  Refresh-Label -Label $Indicator_MD5 -NewText $Script:IndicatorMD5_T -NewForeColor $Script:IndicatorMD5_F -NewBackColor $Script:IndicatorMD5_B
  Refresh-Label -Label $Indicator_RIPEMD160 -NewText $Script:IndicatorRIPEMD160_T -NewForeColor $Script:IndicatorRIPEMD160_F -NewBackColor $Script:IndicatorRIPEMD160_B
  Refresh-Label -Label $Indicator_SHA1 -NewText $Script:IndicatorSHA1_T -NewForeColor $Script:IndicatorSHA1_F -NewBackColor $Script:IndicatorSHA1_B
  Refresh-Label -Label $Indicator_SHA256 -NewText $Script:IndicatorSHA256_T -NewForeColor $Script:IndicatorSHA256_F -NewBackColor $Script:IndicatorSHA256_B
  Refresh-Label -Label $Indicator_SHA384 -NewText $Script:IndicatorSHA384_T -NewForeColor $Script:IndicatorSHA384_F -NewBackColor $Script:IndicatorSHA384_B
  Refresh-Label -Label $Indicator_SHA512 -NewText $Script:IndicatorSHA512_T -NewForeColor $Script:IndicatorSHA512_F -NewBackColor $Script:IndicatorSHA512_B
}


Function Show-FileBrowser {
  [CmdletBinding()]  
  Param ([Parameter(Mandatory)]
         [String]$Title,
         
         [String]$Directory,
         
         [String]$Filter = "All Files (*.*)|*.*"
        )


  $objForm = New-Object System.Windows.Forms.OpenFileDialog
  $objForm.InitialDirectory = $Directory
  $objForm.Filter = $Filter
  $objForm.Title = $Title
  $Show = $objForm.ShowDialog()

  If ($Show -eq "OK") {
    Return $objForm.FileName
  }
  Else {
    Write-Host 'Operation cancelled by user.' -ForegroundColor Yellow
  }
}


<##################################################
            GUI WINDOW\MAIN SCRIPT
##################################################>

<#Create the GUI window to display to the User.#>
$Form_Main = New-Object System.Windows.Forms.Form 
$Form_Main.Text = "$Script:ScriptName"
$Form_Main.Size = New-Object System.Drawing.Size(600,575)
$Form_Main.StartPosition = "CenterScreen"
$Form_Main.KeyPreview = $True
$Form_Main.Add_KeyDown({
  <#Allow pressing the 'Enter' key to shift the focus
  from the currently selected item to the next.#>
  If($_.KeyCode -eq "Enter") {
    If ($TextBox_MACTDES.Focused -eq $True) {
      $TextBox_MD5.Focus()
    }
    ElseIf ($TextBox_MD5.Focused -eq $True) {
      $TextBox_RIPEMD160.Focus()
    }
    ElseIf ($TextBox_RIPEMD160.Focused -eq $True) {
      $TextBox_SHA1.Focus()
    }
    ElseIf ($TextBox_SHA1.Focused -eq $True) {
      $TextBox_SHA256.Focus()
    }
    ElseIf ($TextBox_SHA256.Focused -eq $True) {
      $TextBox_SHA384.Focus()
    }
    ElseIf ($TextBox_SHA384.Focused -eq $True) {
      $TextBox_SHA512.Focus()
    }
    ElseIf ($TextBox_SHA512.Focused -eq $True) {
      $Button_Verify.Focus()
    }
  }
})
$Form_Main.Add_Shown({$Form_Main.Activate();$Button_Browse.Focus()})



<#Create the description text, and add it to the GUI Window.#>
$Label_Desc = New-Object System.Windows.Forms.Label
$Label_Desc.Location = New-Object System.Drawing.Size(05,05)
$Label_Desc.Size = New-Object System.Drawing.Size(500,25)
$Label_Desc.Text = "Click the 'Select File' button to select the file you wish to verify."
$Form_Main.Controls.Add($Label_Desc)



<#Create the label that will identify the Encryption Key path input box,
then create the Encryption Key path input box, and add them to the GUI Window.#>
$Label_FilePath = New-Object System.Windows.Forms.Label
$Label_FilePath.Location = New-Object System.Drawing.Size(05,35)
$Label_FilePath.Size = New-Object System.Drawing.Size(280,15) 
$Label_FilePath.Text = 'File to check:'
$Form_Main.Controls.Add($Label_FilePath) 

$TextBox_FilePath = New-Object System.Windows.Forms.TextBox
$TextBox_FilePath.Location = New-Object System.Drawing.Size(05,50) 
$TextBox_FilePath.Size = New-Object System.Drawing.Size(500,20)
$TextBox_FilePath.ReadOnly = $True
$TextBox_FilePath.Enabled = $False
$Form_Main.Controls.Add($TextBox_FilePath)



<#Create a button to allow the user to browse for and select their
Encryption Key file, and add it to the GUI Window.#>
$Button_Browse = New-Object System.Windows.Forms.Button
$Button_Browse.Location = New-Object System.Drawing.Size(505,49)
$Button_Browse.Size = New-Object System.Drawing.Size(75,22)
$Button_Browse.Text = 'Select File'
$Button_Browse.Add_Click({
  Clear-GUI
  $SF = Show-FileBrowser -Title 'Select a File' -Directory "$Env:USERPROFILE\Desktop" -Filter "All Files (*.*)|*.*"
  $TextBox_FilePath.Text = $SF
  $TextBox_MACTDES.Focus()
})
$Form_Main.Controls.Add($Button_Browse)



<#Create the label that will identify the MACTripleDES Hash input box, then create the
MACTripleDES Hash input box and it's status indicator, and add a ReadOnly text box to
display the files MACTripleDES Hash for visual representation and add them to the GUI Window.#>
$Label_MACTDES = New-Object System.Windows.Forms.Label
$Label_MACTDES.Location = New-Object System.Drawing.Size(10,100) 
$Label_MACTDES.Size = New-Object System.Drawing.Size(100,15)
$Label_MACTDES.Text = 'MACTripleDES:'
$Form_Main.Controls.Add($Label_MACTDES) 

$TextBox_MACTDES = New-Object System.Windows.Forms.TextBox
$TextBox_MACTDES.Location = New-Object System.Drawing.Size(10,115) 
$TextBox_MACTDES.Size = New-Object System.Drawing.Size(560,20) 
$Form_Main.Controls.Add($TextBox_MACTDES)

$TextBox_FileMACTDES = New-Object System.Windows.Forms.TextBox
$TextBox_FileMACTDES.Location = New-Object System.Drawing.Size(10,135) 
$TextBox_FileMACTDES.Size = New-Object System.Drawing.Size(560,20)
$TextBox_FileMACTDES.ReadOnly = $True
$TextBox_FileMACTDES.Enabled = $False
$Form_Main.Controls.Add($TextBox_FileMACTDES)

$Indicator_MACTDES = New-Object System.Windows.Forms.Label
$Indicator_MACTDES = New-Object System.Windows.Forms.Label
$Indicator_MACTDES.Location = New-Object System.Drawing.Size(500,100)
$Indicator_MACTDES.Size = New-Object System.Drawing.Size(70,20)
$Indicator_MACTDES.Font = New-Object System.Drawing.Font('Consolas','10',[System.Drawing.FontStyle]::Bold)
$Indicator_MACTDES.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$Indicator_MACTDES.Text = $Script:IndicatorMACTDES_T
$Indicator_MACTDES.ForeColor = $Script:IndicatorMACTDES_F
$Indicator_MACTDES.BackColor = $Script:IndicatorMACTDES_B
$Form_Main.Controls.Add($Indicator_MACTDES)



<#Create the label that will identify the MD5 Hash input box, then create the
MD5 Hash input box and it's status indicator, and add a ReadOnly text box to
display the files MD5 Hash for visual representation and add them to the GUI Window.#>
$Label_MD5 = New-Object System.Windows.Forms.Label
$Label_MD5.Location = New-Object System.Drawing.Size(10,155) 
$Label_MD5.Size = New-Object System.Drawing.Size(100,15)
$Label_MD5.Text = 'MD5:'
$Form_Main.Controls.Add($Label_MD5) 

$TextBox_MD5 = New-Object System.Windows.Forms.TextBox
$TextBox_MD5.Location = New-Object System.Drawing.Size(10,170) 
$TextBox_MD5.Size = New-Object System.Drawing.Size(560,20) 
$Form_Main.Controls.Add($TextBox_MD5)

$TextBox_FileMD5 = New-Object System.Windows.Forms.TextBox
$TextBox_FileMD5.Location = New-Object System.Drawing.Size(10,190) 
$TextBox_FileMD5.Size = New-Object System.Drawing.Size(560,20)
$TextBox_FileMD5.ReadOnly = $True
$TextBox_FileMD5.Enabled = $False
$Form_Main.Controls.Add($TextBox_FileMD5)

$Indicator_MD5 = New-Object System.Windows.Forms.Label
$Indicator_MD5 = New-Object System.Windows.Forms.Label
$Indicator_MD5.Location = New-Object System.Drawing.Size(500,155)
$Indicator_MD5.Size = New-Object System.Drawing.Size(70,20)
$Indicator_MD5.Font = New-Object System.Drawing.Font('Consolas','10',[System.Drawing.FontStyle]::Bold)
$Indicator_MD5.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$Indicator_MD5.Text = $Script:IndicatorMD5_T
$Indicator_MD5.ForeColor = $Script:IndicatorMD5_F
$Indicator_MD5.BackColor = $Script:IndicatorMD5_B
$Form_Main.Controls.Add($Indicator_MD5)



<#Create the label that will identify the RIPEMD160 Hash input box, then create the
RIPEMD160 Hash input box and it's status indicator, and add a ReadOnly text box to
display the files RIPEMD160 Hash for visual representation and add them to the GUI Window.#>
$Label_RIPEMD160 = New-Object System.Windows.Forms.Label
$Label_RIPEMD160.Location = New-Object System.Drawing.Size(10,210) 
$Label_RIPEMD160.Size = New-Object System.Drawing.Size(100,15)
$Label_RIPEMD160.Text = 'RIPEMD160:'
$Form_Main.Controls.Add($Label_RIPEMD160) 

$TextBox_RIPEMD160 = New-Object System.Windows.Forms.TextBox
$TextBox_RIPEMD160.Location = New-Object System.Drawing.Size(10,225) 
$TextBox_RIPEMD160.Size = New-Object System.Drawing.Size(560,20) 
$Form_Main.Controls.Add($TextBox_RIPEMD160)

$TextBox_FileRIPEMD160 = New-Object System.Windows.Forms.TextBox
$TextBox_FileRIPEMD160.Location = New-Object System.Drawing.Size(10,245) 
$TextBox_FileRIPEMD160.Size = New-Object System.Drawing.Size(560,20)
$TextBox_FileRIPEMD160.ReadOnly = $True
$TextBox_FileRIPEMD160.Enabled = $False
$Form_Main.Controls.Add($TextBox_FileRIPEMD160)

$Indicator_RIPEMD160 = New-Object System.Windows.Forms.Label
$Indicator_RIPEMD160 = New-Object System.Windows.Forms.Label
$Indicator_RIPEMD160.Location = New-Object System.Drawing.Size(500,210)
$Indicator_RIPEMD160.Size = New-Object System.Drawing.Size(70,20)
$Indicator_RIPEMD160.Font = New-Object System.Drawing.Font('Consolas','10',[System.Drawing.FontStyle]::Bold)
$Indicator_RIPEMD160.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$Indicator_RIPEMD160.Text = $Script:IndicatorRIPEMD160_T
$Indicator_RIPEMD160.ForeColor = $Script:IndicatorRIPEMD160_F
$Indicator_RIPEMD160.BackColor = $Script:IndicatorRIPEMD160_B
$Form_Main.Controls.Add($Indicator_RIPEMD160)



<#Create the label that will identify the SHA1 Hash input box, then create the
SHA1 Hash input box and it's status indicator, and add a ReadOnly text box to
display the files SHA1 Hash for visual representation and add them to the GUI Window.#>
$Label_SHA1 = New-Object System.Windows.Forms.Label
$Label_SHA1.Location = New-Object System.Drawing.Size(10,265) 
$Label_SHA1.Size = New-Object System.Drawing.Size(100,15)
$Label_SHA1.Text = 'SHA-1:'
$Form_Main.Controls.Add($Label_SHA1) 

$TextBox_SHA1 = New-Object System.Windows.Forms.TextBox
$TextBox_SHA1.Location = New-Object System.Drawing.Size(10,280) 
$TextBox_SHA1.Size = New-Object System.Drawing.Size(560,20) 
$Form_Main.Controls.Add($TextBox_SHA1)

$TextBox_FileSHA1 = New-Object System.Windows.Forms.TextBox
$TextBox_FileSHA1.Location = New-Object System.Drawing.Size(10,300) 
$TextBox_FileSHA1.Size = New-Object System.Drawing.Size(560,20)
$TextBox_FileSHA1.ReadOnly = $True
$TextBox_FileSHA1.Enabled = $False
$Form_Main.Controls.Add($TextBox_FileSHA1)

$Indicator_SHA1 = New-Object System.Windows.Forms.Label
$Indicator_SHA1 = New-Object System.Windows.Forms.Label
$Indicator_SHA1.Location = New-Object System.Drawing.Size(500,265)
$Indicator_SHA1.Size = New-Object System.Drawing.Size(70,20)
$Indicator_SHA1.Font = New-Object System.Drawing.Font('Consolas','10',[System.Drawing.FontStyle]::Bold)
$Indicator_SHA1.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$Indicator_SHA1.Text = $Script:IndicatorSHA1_T
$Indicator_SHA1.ForeColor = $Script:IndicatorSHA1_F
$Indicator_SHA1.BackColor = $Script:IndicatorSHA1_B
$Form_Main.Controls.Add($Indicator_SHA1)



<#Create the label that will identify the SHA256 Hash input box, then create the
SHA256 Hash input box and it's status indicator, and add a ReadOnly text box to
display the files SHA256 Hash for visual representation and add them to the GUI Window.#>
$Label_SHA256 = New-Object System.Windows.Forms.Label
$Label_SHA256.Location = New-Object System.Drawing.Size(10,320) 
$Label_SHA256.Size = New-Object System.Drawing.Size(100,15)
$Label_SHA256.Text = 'SHA-256:'
$Form_Main.Controls.Add($Label_SHA256) 

$TextBox_SHA256 = New-Object System.Windows.Forms.TextBox
$TextBox_SHA256.Location = New-Object System.Drawing.Size(10,335) 
$TextBox_SHA256.Size = New-Object System.Drawing.Size(560,20) 
$Form_Main.Controls.Add($TextBox_SHA256)

$TextBox_FileSHA256 = New-Object System.Windows.Forms.TextBox
$TextBox_FileSHA256.Location = New-Object System.Drawing.Size(10,355) 
$TextBox_FileSHA256.Size = New-Object System.Drawing.Size(560,20)
$TextBox_FileSHA256.ReadOnly = $True
$TextBox_FileSHA256.Enabled = $False
$Form_Main.Controls.Add($TextBox_FileSHA256)

$Indicator_SHA256 = New-Object System.Windows.Forms.Label
$Indicator_SHA256 = New-Object System.Windows.Forms.Label
$Indicator_SHA256.Location = New-Object System.Drawing.Size(500,320)
$Indicator_SHA256.Size = New-Object System.Drawing.Size(70,20)
$Indicator_SHA256.Font = New-Object System.Drawing.Font('Consolas','10',[System.Drawing.FontStyle]::Bold)
$Indicator_SHA256.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$Indicator_SHA256.Text = $Script:IndicatorSHA256_T
$Indicator_SHA256.ForeColor = $Script:IndicatorSHA256_F
$Indicator_SHA256.BackColor = $Script:IndicatorSHA256_B
$Form_Main.Controls.Add($Indicator_SHA256)



<#Create the label that will identify the SHA384 Hash input box, then create the
SHA384 Hash input box and it's status indicator, and add a ReadOnly text box to
display the files SHA384 Hash for visual representation and add them to the GUI Window.#>
$Label_SHA384 = New-Object System.Windows.Forms.Label
$Label_SHA384.Location = New-Object System.Drawing.Size(10,375) 
$Label_SHA384.Size = New-Object System.Drawing.Size(100,15)
$Label_SHA384.Text = 'SHA-384:'
$Form_Main.Controls.Add($Label_SHA384) 

$TextBox_SHA384 = New-Object System.Windows.Forms.TextBox
$TextBox_SHA384.Location = New-Object System.Drawing.Size(10,390) 
$TextBox_SHA384.Size = New-Object System.Drawing.Size(560,20) 
$Form_Main.Controls.Add($TextBox_SHA384)

$TextBox_FileSHA384 = New-Object System.Windows.Forms.TextBox
$TextBox_FileSHA384.Location = New-Object System.Drawing.Size(10,410) 
$TextBox_FileSHA384.Size = New-Object System.Drawing.Size(560,20)
$TextBox_FileSHA384.ReadOnly = $True
$TextBox_FileSHA384.Enabled = $False
$Form_Main.Controls.Add($TextBox_FileSHA384)

$Indicator_SHA384 = New-Object System.Windows.Forms.Label
$Indicator_SHA384 = New-Object System.Windows.Forms.Label
$Indicator_SHA384.Location = New-Object System.Drawing.Size(500,375)
$Indicator_SHA384.Size = New-Object System.Drawing.Size(70,20)
$Indicator_SHA384.Font = New-Object System.Drawing.Font('Consolas','10',[System.Drawing.FontStyle]::Bold)
$Indicator_SHA384.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$Indicator_SHA384.Text = $Script:IndicatorSHA384_T
$Indicator_SHA384.ForeColor = $Script:IndicatorSHA384_F
$Indicator_SHA384.BackColor = $Script:IndicatorSHA384_B
$Form_Main.Controls.Add($Indicator_SHA384)



<#Create the label that will identify the SHA512 Hash input box, then create the
SHA512 Hash input box and it's status indicator, and add a ReadOnly text box to
display the files SHA512 Hash for visual representation and add them to the GUI Window.#>
$Label_SHA512 = New-Object System.Windows.Forms.Label
$Label_SHA512.Location = New-Object System.Drawing.Size(10,430) 
$Label_SHA512.Size = New-Object System.Drawing.Size(100,15)
$Label_SHA512.Text = 'SHA-512:'
$Form_Main.Controls.Add($Label_SHA512) 

$TextBox_SHA512 = New-Object System.Windows.Forms.TextBox
$TextBox_SHA512.Location = New-Object System.Drawing.Size(10,445) 
$TextBox_SHA512.Size = New-Object System.Drawing.Size(560,20) 
$Form_Main.Controls.Add($TextBox_SHA512)

$TextBox_FileSHA512 = New-Object System.Windows.Forms.TextBox
$TextBox_FileSHA512.Location = New-Object System.Drawing.Size(10,465) 
$TextBox_FileSHA512.Size = New-Object System.Drawing.Size(560,20)
$TextBox_FileSHA512.ReadOnly = $True
$TextBox_FileSHA512.Enabled = $False
$Form_Main.Controls.Add($TextBox_FileSHA512)

$Indicator_SHA512 = New-Object System.Windows.Forms.Label
$Indicator_SHA512 = New-Object System.Windows.Forms.Label
$Indicator_SHA512.Location = New-Object System.Drawing.Size(500,430)
$Indicator_SHA512.Size = New-Object System.Drawing.Size(70,20)
$Indicator_SHA512.Font = New-Object System.Drawing.Font('Consolas','10',[System.Drawing.FontStyle]::Bold)
$Indicator_SHA512.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$Indicator_SHA512.Text = $Script:IndicatorSHA512_T
$Indicator_SHA512.ForeColor = $Script:IndicatorSHA512_F
$Indicator_SHA512.BackColor = $Script:IndicatorSHA512_B
$Form_Main.Controls.Add($Indicator_SHA512)



<#Create the 'Verify' button that will start the Hash
Checking process, and add it to the GUI Window.#>
$Button_Verify = New-Object System.Windows.Forms.Button
$Button_Verify.Location = New-Object System.Drawing.Size(112,500)
$Button_Verify.Size = New-Object System.Drawing.Size(75,23)
$Button_Verify.Text = 'Verify'
$Button_Verify.Add_Click({
  
  <#Verify a file has been selected.#>
  If ($TextBox_FilePath.Text -eq $Null -or $TextBox_Username.Text -eq '') {
    [System.Windows.MessageBox]::Show("Please select the file you would like to verify.","No File Chosen",'OK','Error')
    $Button_Browse.Focus()
  }
  Else {

    <#Detect and store all Hashes from the selected file.#>
    $TextBox_FileMACTDES.Text = (Get-FileHash -Path $TextBox_FilePath.Text -Algorithm MACTripleDES).Hash
    $TextBox_FileMD5.Text = (Get-FileHash -Path $TextBox_FilePath.Text -Algorithm MD5).Hash
    $TextBox_FileRIPEMD160.Text = (Get-FileHash -Path $TextBox_FilePath.Text -Algorithm RIPEMD160).Hash
    $TextBox_FileSHA1.Text = (Get-FileHash -Path $TextBox_FilePath.Text -Algorithm SHA1).Hash
    $TextBox_FileSHA256.Text = (Get-FileHash -Path $TextBox_FilePath.Text -Algorithm SHA256).Hash
    $TextBox_FileSHA384.Text = (Get-FileHash -Path $TextBox_FilePath.Text -Algorithm SHA384).Hash
    $TextBox_FileSHA512.Text = (Get-FileHash -Path $TextBox_FilePath.Text -Algorithm SHA512).Hash


    <#If a MACTripleDESHash is present in the MACTripleDES textbox and the file has a MACTripleDES hash, compare them and indicate the results#>
    If (![String]::IsNullOrEmpty($TextBox_MACTDES.Text) -and ![String]::IsNullOrEmpty($TextBox_FileMACTDES.Text)) {
      If ($TextBox_MACTDES.Text -eq $TextBox_FileMACTDES.Text) {
        $Script:IndicatorMACTDES_T = 'MATCH'
        $Script:IndicatorMACTDES_F = 'Green'
      }
      Else {
        $Script:IndicatorMACTDES_T = 'FAIL'
        $Script:IndicatorMACTDES_F = 'Red'
      }
      Refresh-Label -Label $Indicator_MACTDES -NewText $Script:IndicatorMACTDES_T -NewForeColor $Script:IndicatorMACTDES_F -NewBackColor $Script:IndicatorMACTDES_B
    }

    <#If a MD5 is present in the MD5 textbox and the file has a MD5 hash, compare them and indicate the results#>
    If (![String]::IsNullOrEmpty($TextBox_MD5.Text) -and ![String]::IsNullOrEmpty($TextBox_FileMD5.Text)) {
      If ($TextBox_MD5.Text -eq $TextBox_FileMD5.Text) {
        $Script:IndicatorMD5_T = 'MATCH'
        $Script:IndicatorMD5_F = 'Green'
      }
      Else {
        $Script:IndicatorMD5_T = 'FAIL'
        $Script:IndicatorMD5_F = 'Red'
      }
      Refresh-Label -Label $Indicator_MD5 -NewText $Script:IndicatorMD5_T -NewForeColor $Script:IndicatorMD5_F
    }

    <#If a RIPEMD160 is present in the RIPEMD160 textbox and the file has a RIPEMD160 hash, compare them and indicate the results#>
    If (![String]::IsNullOrEmpty($TextBox_RIPEMD160.Text) -and ![String]::IsNullOrEmpty($TextBox_FileRIPEMD160.Text)) {
      If ($TextBox_RIPEMD160.Text -eq $TextBox_FileRIPEMD160.Text) {
        $Script:IndicatorRIPEMD160_T = 'MATCH'
        $Script:IndicatorRIPEMD160_F = 'Green'
      }
      Else {
        $Script:IndicatorRIPEMD160_T = 'FAIL'
        $Script:IndicatorRIPEMD160_F = 'Red'
      }
      Refresh-Label -Label $Indicator_RIPEMD160 -NewText $Script:IndicatorRIPEMD160_T -NewForeColor $Script:IndicatorRIPEMD160_F
    }

    <#If a SHA1 is present in the SHA1 textbox and the file has a SHA1 hash, compare them and indicate the results#>
    If (![String]::IsNullOrEmpty($TextBox_SHA1.Text) -and ![String]::IsNullOrEmpty($TextBox_FileSHA1.Text)) {
      If ($TextBox_SHA1.Text -eq $TextBox_FileSHA1.Text) {
        $Script:IndicatorSHA1_T = 'MATCH'
        $Script:IndicatorSHA1_F = 'Green'
      }
      Else {
        $Script:IndicatorSHA1_T = 'FAIL'
        $Script:IndicatorSHA1_F = 'Red'
      }
      Refresh-Label -Label $Indicator_SHA1 -NewText $Script:IndicatorSHA1_T -NewForeColor $Script:IndicatorSHA1_F
    }

    <#If a SHA256 is present in the SHA256 textbox and the file has a SHA256 hash, compare them and indicate the results#>
    If (![String]::IsNullOrEmpty($TextBox_SHA256.Text) -and ![String]::IsNullOrEmpty($TextBox_FileSHA256.Text)) {
      If ($TextBox_SHA256.Text -eq $TextBox_FileSHA256.Text) {
        $Script:IndicatorSHA256_T = 'MATCH'
        $Script:IndicatorSHA256_F = 'Green'
      }
      Else {
        $Script:IndicatorSHA256_T = 'FAIL'
        $Script:IndicatorSHA256_F = 'Red'
      }
      Refresh-Label -Label $Indicator_SHA256 -NewText $Script:IndicatorSHA256_T -NewForeColor $Script:IndicatorSHA256_F
    }

    <#If a SHA384 is present in the SHA384 textbox and the file has a SHA384 hash, compare them and indicate the results#>
    If (![String]::IsNullOrEmpty($TextBox_SHA384.Text) -and ![String]::IsNullOrEmpty($TextBox_FileSHA384.Text)) {
      If ($TextBox_SHA384.Text -eq $TextBox_FileSHA384.Text) {
        $Script:IndicatorSHA384_T = 'MATCH'
        $Script:IndicatorSHA384_F = 'Green'
      }
      Else {
        $Script:IndicatorSHA384_T = 'FAIL'
        $Script:IndicatorSHA384_F = 'Red'
      }
      Refresh-Label -Label $Indicator_SHA384 -NewText $Script:IndicatorSHA384_T -NewForeColor $Script:IndicatorSHA384_F
    }

    <#If a SHA512 is present in the SHA512 textbox and the file has a SHA512 hash, compare them and indicate the results#>
    If (![String]::IsNullOrEmpty($TextBox_SHA512.Text) -and ![String]::IsNullOrEmpty($TextBox_FileSHA512.Text)) {
      If ($TextBox_SHA512.Text -eq $TextBox_FileSHA512.Text) {
        $Script:IndicatorSHA512_T = 'MATCH'
        $Script:IndicatorSHA512_F = 'Green'
      }
      Else {
        $Script:IndicatorSHA512_T = 'FAIL'
        $Script:IndicatorSHA512_F = 'Red'
      }
      Refresh-Label -Label $Indicator_SHA512 -NewText $Script:IndicatorSHA512_T -NewForeColor $Script:IndicatorSHA512_F
    }
  }
})
$Form_Main.Controls.Add($Button_Verify)



<#Create the 'Clear' button that will start the Hash
Checking process, and add it to the GUI Window.#>
$Button_Clear = New-Object System.Windows.Forms.Button
$Button_Clear.Location = New-Object System.Drawing.Size(390,500)
$Button_Clear.Size = New-Object System.Drawing.Size(75,23)
$Button_Clear.Text = 'Clear'
$Button_Clear.Add_Click({Clear-GUI;Clear-Host})
$Form_Main.Controls.Add($Button_Clear)



<#Display the GUI Window now that all of it's components have been created.#>
$Form_Main.Topmost = $False
$Form_Main.ShowDialog()