   M S B A M L   `   `   `  ����L  HDigital Signature, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null5clr-namespace:Digital_SignatureDigital_Signature  5      "    Digital_Signature.MainWindow   5      W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5      R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5      @d2http://schemas.microsoft.com/expression/blend/2008     5      1localclr-namespace:Digital_Signature     5      U QMaterialDesignThemes.Wpf, Version=2.6.0.325, Culture=neutral, PublicKeyToken=nullFmaterialDesign1http://materialdesigninxaml.net/winfx/xaml/themes  5      Dmc;http://schemas.openxmlformats.org/markup-compatibility/2006  5        � Title$  
MainWindow��5	      $
��1100��5
      $	��630��5         MaterialDesignPaper#���   5      $X��Rpack://application:,,,/MaterialDesignThemes.Wpf;component/Resources/Roboto/#Roboto)�5      $��Medium"�5        MaterialDesignBody#���  5      &   System.Windows.Media.TextOptions   TextFormattingMode$ Ideal=�5         TextRenderingMode$
 Auto=�5       � WindowStartupLocation$ CenterScreen=�5      .��5      � .+�5   
   '  !MaterialDesignThemes.Wpf.PopupBox  $��	0,0,30,30q�5      $��Right=�5      $��Bottom=�5       - )MaterialDesignMultiFloatingActionPopupBox#��[ 5         ToggleCheckedContent 5      '  !MaterialDesignThemes.Wpf.PackIcon  5      $��20��5      $��20��5      $��Center=�5      $��Center=�5      �  �ControlzEx.PackIconBase`1[[MaterialDesignThemes.Wpf.PackIconKind, MaterialDesignThemes.Wpf, Version=2.6.0.325, Culture=neutral, PublicKeyToken=null]]   Kind$ Close=�5          PopupContent. 5"      �� .+�5#      �� -   5         ��Name$ newFile��5$       � ToolTip$ Add New File��5&      .��5'        $��24��5(      $��24��5)      $
 File=�5*      5+      5,      5-      �� 5.   
   -   5        $ 	verifyBtn��5/      $��
0,0,100,30q�50      $��Right=�51      $��Bottom=�52       * &MaterialDesignFloatingActionDarkButton#��[ 54      $ Verify Signature��55      .��56        $��24��57      $��24��58      $ CheckAll=�59      5:      �� 5;   
   -   5        $ hashBtn��5<      $��
0,0,170,30q�5=      $��Right=�5>      $��Bottom=�5?      #��[ 5A      $ 	Hash File��5B      .��5C        $��24��5D      $��24��5E      $ Hashtag=�5F      5G      �� 5H   
   -   5        	 ��Name$	 filePathTextBox��5I      $	��565��5J      $��
0,0,240,40q�5K      $��Right=�5L      $��Bottom=�5M      )  #MaterialDesignThemes.Wpf.HintAssist
   Hint$
 	File Path��5N       % !MaterialDesignFloatingHintTextBox#��[ 5O      �� 5Q   
    �� Orientation$ Vertical=�6   .+�5R      (  "MaterialDesignThemes.Wpf.ColorZone  $��16q�5S      +  %MaterialDesignThemes.Wpf.ShadowAssist   ShadowDepth$ Depth3=�5T         CornerRadius$ 3��5U         Mode$ PrimaryDark=�5V      .��5W      �� $ 
Horizontal=�6   .+�5X      d�  ' #MaterialDesignHamburgerToggleButton#���  6#   �� 5Y      $��16,0,0,0q�5Z      $��Center=�5[         MaterialDesignTitleTextBlock#��[ 5\      DIGITAL SIGNATURE5^      5_      5`      �� 5a      $��30q�6   $ 
Horizontal=�6%   .+�5b      �� $ Vertical=�6   .+�5c      #  MaterialDesignThemes.Wpf.Card  $	��220��6*   .��5d      �  � RowDefinitions 5e      �� 5f   "   $	��140 �60   �� 5g   "   $��* �60   �� 5h   "   $
��Auto �60   �� 5i   "   $
��Auto �60   �� 5j   "   $
��Auto �60   �� 5k   "   $
��Auto �60   �� 5l   "   $
��Auto �60   .+�5n      �� $	��140��5o   !   $��images/net.png��5p   !   $��UniformToFill=�5q   !   �� 5r      $��0��5s   !   $��
0,0,16,-20q�5t   !   $��Right=�5u   !   $��Bottom=�5v   !   
������� 0 ,MaterialDesignFloatingActionMiniAccentButton#��[ 5x   !   .��5y   "     $ Network=�6:   5z      �� 5{      $��1��6)   $��8,24,8,4q�66   .+�5|   "   �� $��0q�6,      MaterialDesignBody2TextBlock#��[ 67   CREATE CONNECTION5~   #   5      �� 5�      $��2��5�   !   $
��Auto��5�   !   $��8,1,8,0q�5�   !    	 MaterialDesignDarkSeparator#��[	 5�   !   �� 5�      -   5        $	 ipAddressTextBox��5�   !   $��3��5�   !   $��10q�5�   !   $
 
IP ADDRESS��5�   !   #��[ 5�   !   �� 5�      -   5        $	 portTextBox��5�   !   $��4��5�   !   $��10,10,10,20q�5�   !   $

 PORT��5�   !   #��[ 5�   !   �� 5�      $��5��5�   !   $
��Auto��5�   !   $��0q�5�   !   #��[	 5�   !   �� 5�      $��6��6)   $ 
Horizontal=�66   .+�5�   "   �� -   5        $ ServeButton��5�   %   $	��100��5�   %   $��5q�5�   %   $
��Left=�5�   %    
 MaterialDesignFlatButton#��[
 5�   %   $ Create Server��5�   %   .��6=   SERVE5�   #   �� 5�   "   -   5        $ connectServerBtn��5�   %   $	��100��5�   %   $��5q�5�   %   $
��Left=�5�   %   #��[
 5�   %   $ Connect to Server��5�   %   .��6A   	CONNECT5�   #   5�      5�      5�      � 5�      .+�5�      � -	   5         �Name$ progressBar��5�      $��30��5�      $��30��5�      $��	0,30,0,10q�5�       � IsIndeterminate .  % !MaterialDesignCircularProgressBar#��[ 5�       � Value$ 0Q�5�      �� 5�      -
   5        $��
checkedBtn��5�      $��30��5�      $��30��5�      $��	0,30,0,10q�5�       ( $MaterialDesignTextFieldBoxBackground#���  5�      
��� � �  MaterialDesignIconButton#��[ 5�      $ MaterialDesignIconButton��5�      .��5�        $ Check=�66   5�      5�      �� 5�      -   5         ��Name$ progressTextBlock��5�      $��Center=�5�         MaterialDesignBody1TextBlock#��[ 5�       Connecting to given Ip address5�      5�      �� 5�      .+�5�      �� -   5         ��Name$; 5MaterialDesignOutlinedTextFieldTextBoxEnabledComboBox��5�      $��32,0,0,8q�5�       d� 	IsChecked$
 TrueY�5�      .��6*   Enabled Console5�      �� 5�      -   5        $	 consoleTextBox��5�      $	��770��5�      $	��325��5�      $��32,0,0,0q�5�      $	��Top=�5�       �� AcceptsReturn . $��Consolas)�5�       * &MaterialDesignOutlinedTextFieldTextBox#��[ 5�       �� TextWrapping$
 Wrap=�5�      " �� VerticalScrollBarVisibility$
 Auto=�5�      {�5�      ��  �� Path$ 	IsChecked� �� ElementName$; 5MaterialDesignOutlinedTextFieldTextBoxEnabledComboBox��5�      5�      5�      5�      '	  !MaterialDesignThemes.Wpf.Snackbar	  5�   
   -   5         	 Name$ SnackbarTwo��5�   "    	  IsActive .   	  Message. 5�      .
  (MaterialDesignThemes.Wpf.SnackbarMessage
  -   5         
  ActionContent$ Ok��5�      $��Content��5�      5�      5�      5�      