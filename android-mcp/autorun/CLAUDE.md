# Android app workflow (auto-run on the phone)

This project is an Android app developed with the `claude` CLI. A rooted
OnePlus 7 Pro is connected over ADB, and the **android-control** MCP server is
available. Use it to run and verify the app on the real device automatically —
do not wait to be asked to open or test the app.

## After every build that succeeds

When you finish writing or changing the app and it builds, **automatically**:

1. Build the debug APK if it isn't already built:
   `./gradlew assembleDebug`
2. Install it and open it on the phone in one step with the MCP tool:
   `install_and_launch(apk_path="app/build/outputs/apk/debug/app-debug.apk", package="<applicationId>")`
   - Use the app's real `applicationId` from `app/build.gradle` as `package`.
   - If you only need to relaunch an already-installed app, use
     `launch_and_read(package="<applicationId>")` instead.
3. The tool returns the app's first screen as a list of UI elements. **Read it**
   and confirm the app launched and looks right (no crash dialog, expected
   text/buttons present).
4. If a feature is testable from the UI, exercise it with the act-and-see tools:
   `tap_text_and_read("<button label>")`, `input_text(...)`, `screen_text()`.
   After interacting, read the screen again to verify the result.
5. If the screen is blank to the accessibility tree (custom/canvas UI), fall
   back to `ocr_screen()` to read it, and `screenshot()` if you need pixels.
6. If the app crashed or misbehaves, pull the reason with
   `logcat(filter_text="<applicationId>")` (or `AndroidRuntime`), fix the code,
   rebuild, and repeat from step 1.

## Device prep

- Before launching, make sure the screen is on and unlocked: `wake()` then
  `unlock(pin="...")` if the device is secured.
- If a previous version is running, `stop_app("<applicationId>")` first for a
  clean start.

## Notes

- Prefer the `*_and_read` tools so you see the result of each action without a
  separate call.
- Tap by visible label (`tap_text`) rather than raw coordinates whenever the
  element is in the UI tree.
