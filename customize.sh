SKIPUNZIP=0

if [ "$ARCH" != "arm64" ]; then
  ui_print "! This module supports arm64-v8a only."
  ui_print "! Your device reports ARCH=$ARCH"
  abort
fi

if ! magisk --denylist status >/dev/null 2>&1; then
  ui_print "- Magisk denylist not detected; continuing."
fi

if magisk --denylist status >/dev/null 2>&1; then
  if magisk --denylist ls | grep -q '^com\.mojang\.minecraftpe'; then
    ui_print "! com.mojang.minecraftpe is in the Magisk DenyList."
    ui_print "! Remove it from DenyList or Zygisk will skip injection."
  fi
fi

ui_print "- Installed. Reboot, then launch Minecraft."
ui_print "- Volume Up (long press) toggles the menu."
set_perm_recursive "$MODPATH" 0 0 0755 0644
