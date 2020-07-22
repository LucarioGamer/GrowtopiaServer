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


add_achieve_button

add_button

add_button_with_icon

add_checkbox

add_checkicon

add_clothes

add_confirm_item_picker

add_dual_layer_icon_label

add_fish_info

add_image_button

add_item

add_item_picker

add_label

add_label_with_ele_icon

add_label_with_icon

add_notification

add_player_info

add_player_picker

add_quick_exit

add_slot

add_small_font_button

add_smalltext

add_smalltext_forced

add_smalltext_forced_alpha

add_smalltext|

add_spacer|

add_tab_button|

add_text_input|

add_text_input_password|

add_textbox|

add_url_button|


