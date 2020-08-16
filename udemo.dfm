object Form1: TForm1
  Left = 746
  Top = 290
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsToolWindow
  Caption = 'Injection DEMO'
  ClientHeight = 234
  ClientWidth = 523
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -14
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  OnCloseQuery = FormCloseQuery
  OnCreate = FormCreate
  PixelsPerInch = 120
  TextHeight = 16
  object Label1: TLabel
    Left = 30
    Top = 10
    Width = 90
    Height = 16
    Caption = 'Process Name'
  end
  object Label2: TLabel
    Left = 246
    Top = 30
    Width = 20
    Height = 16
    Caption = 'OR'
  end
  object Label3: TLabel
    Left = 295
    Top = 10
    Width = 22
    Height = 16
    Caption = 'PID'
  end
  object Button1: TButton
    Left = 30
    Top = 98
    Width = 454
    Height = 31
    Caption = 'Inject DLL'
    TabOrder = 0
    OnClick = Button1Click
  end
  object txtprocess: TEdit
    Left = 30
    Top = 30
    Width = 188
    Height = 24
    TabOrder = 1
    Text = 'explorer.exe'
  end
  object txtpid: TEdit
    Left = 295
    Top = 30
    Width = 189
    Height = 24
    TabOrder = 2
  end
  object RadioButton1: TRadioButton
    Left = 30
    Top = 69
    Width = 168
    Height = 21
    Caption = 'CreateRemoteThread'
    Checked = True
    TabOrder = 3
    TabStop = True
  end
  object RadioButton2: TRadioButton
    Left = 187
    Top = 69
    Width = 169
    Height = 21
    Caption = 'RtlCreateUserThread'
    TabOrder = 4
  end
  object RadioButton3: TRadioButton
    Left = 335
    Top = 69
    Width = 139
    Height = 21
    Caption = 'NtCreateThreadEx'
    TabOrder = 5
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 215
    Width = 523
    Height = 19
    Panels = <>
    SimplePanel = True
  end
  object txtdll: TEdit
    Left = 30
    Top = 138
    Width = 454
    Height = 24
    TabOrder = 7
    Text = 'c:\_apps\hook.dll'
  end
  object txtdata: TEdit
    Left = 32
    Top = 176
    Width = 457
    Height = 24
    TabOrder = 8
    Text = 'data'
  end
end
