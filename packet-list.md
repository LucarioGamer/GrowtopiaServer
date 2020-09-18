The Known and The Latest Packet/action List

**PACKETS**

OnAddNotification: appendString "tile location", appendString "Message", appendString "sound location", appendInt 0.

**OnConsoleMessage: appendString "message".**

OnCountryState: appendString "tile location" & `memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);`

**OnDialogRequest: appendString: "dialog string".**

OnDisguiseChanged: appendIntx blockid. & `memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);`

**OnGuildDataChanged: appendIntx 41179607, appendIntx 41179607, appendIntx flag, appendIntx 0.**

OnInvis: appendInt 1 or 0 (bool) & `memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);`

**OnItemEffect: appendIntx effectid.**

OnParticleEffect: appendIntx effectid, appendFloat x and y.

**OnParticleEffectV2: appendIntx effectid, appendFloat x and y.**

OnSetBux: appendInt gemamount.

**OnSetClothing: appendFloat (cloth_hair, cloth_shirt, cloth_pants), appendFloat (cloth_feet, cloth_face, cloth_hand), appendFloat (cloth_back, cloth_mask, cloth_necklace), appendIntx skinColor, appendFloat (cloth_ances, 0.0f, 0.0f) & `memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);`**

OnSetCurrentWeather: appendInt weatherid.

**OnSetFreezeState: appendIntx 1-0 (bool).**

OnSetPos: appendFloat (x, y).

**OnTalkBubble: appendIntx netid, appendString text, appendIntx 0.**

OnTextOverlay: appendString text.

**ACTION LIST**

action|AccountSecuritylocation|pausemenu

action|buyitem|

action|chaching

action|dialog_returndialog_name|

action|drop|itemID|

action|enter_game

action|eventmenu

action|eventmenulocation|pausemenu

action|friends

action|friendslocation|pausemenu

action|growid

action|helpmenulocation|pausemenu

action|houston_validation_done

action|info|itemID|

action|input|text|

action|killstoreitem|

action|mod_tradeitemID|

action|quit

action|quit_to_exit

action|refresh_item_data

action|rem_tradeitemID|

action|respawn

action|respawn_spike

action|respawn_spiketileX|

action|setFilterfiltering|

action|setGDPRGDPR|

action|setRoleIconroleType|

action|setRoleSkinroleType|

action|setSkincolor|

action|storelocation|bottommenu

action|storelocation|gem

action|storelocation|pausemenu

action|trade_acceptstatus|

action|trade_cancel

action|trade_lockstatus|

action|trade_startednetid|

action|trash|itemID|

action|UbiclubMenulocation|pausemenu

action|validate_worldname|

action|wrench|netid|


**DIALOG UI PACKETS**

** The example might wrong **

add_achieve_button
example :
 - add_achieve|tittle |description text|left|achievement icon id|

add_button
example : 
 - add_button|button name|button text|


add_button_with_icon
 
 
 
 
add_checkbox
example : 
 - add_checkbox|checkbox name|checkbox text|0| - non checked
 - add_checkbox|checkbox name|checkbox text|1| - checked

add_checkicon

add_clothes

add_confirm_item_picker

add_dual_layer_icon_label
example : 
 - add_duel_layer_icon_label|label text|background item id|foreground item id|duel layer icon size|


add_fish_info




add_image_button
example :
 - add_image_button|banner|interface/large/news_banner.rttex|noflags|||
 
 
add_item

add_item_picker
example : 
 - add_item_picker|item picker name|button text|title text|


add_label
example : 
 - add_label|text|
 
 
add_label_with_ele_icon

add_label_with_icon
example :
 - add_label_with_icon|small|example text|left|item id|
 - add_label_with_icon|big|example text|left|item id|
 
 
add_notification

add_player_info
example:
- add_player_info|player_name|level |current number|number need reach|


add_player_picker
example:
- add_player_picker|player_picker name |button_name|


add_quick_exit
 - none
 
add_slot




add_small_font_button



 
add_smalltext
example: 
 - add_smalltext|text|left|
 
 
add_smalltext_forced
example:
 - add_smalltext_forced| text |left|
 
 
add_smalltext_forced_alpha
example:
 - add_smalltext_forced_alpha| text | size |left|
 
 
add_spacer|
example :
 - add_spacer|big|
 - add_spacer|small|


add_tab_button|
example :
 - TODO
 
 
add_text_input|
example :
 - add_text_input|text_input name|text_input text | default input text|max text length|


add_text_input_password|
example :
 - add_text_input_password|text_input_password name|text_input_password text | default input_password text|max input length|
 
 
add_textbox|
example : 
 - add_textbox|textbox text|
 
  
add_url_button|
example : 
 - add_url_button| url button text| link www.google.com |message box| 
 - add_url_button||button text|NOFLAGS|OPENWORLD|world name|

end_dialog|
example : 
 - end_dialog|dialog name|Cancel|OK|
 
  
