# jadx-copy-as-frida

A [jadx](https://github.com/skylot/jadx) plugin that adds right-click Frida script generation to the decompiled code view. Click on any method or field, copy a ready-to-run Frida hook script to your clipboard.

## Features

### Method Hooks (right-click a method)

| Menu Item | Description |
|---|---|
| **Frida: Hook & log args/ret** | Logs each argument and the return value using `send()` |
| **Frida: Return true** | Bypass — forces the method to return `true` |
| **Frida: Return false** | Bypass — forces the method to return `false` |
| **Frida: Trace call + stack** | Logs the call and a full Java stack trace |
| **Frida: Modify arguments** | Generates editable placeholders for each argument, logs the return value |
| **Frida: Conditional breakpoint** | `Thread.sleep(5000)` pause when your condition matches — edit the `if` statement |
| **Frida: Dump all fields** | When the method is called, dumps every field of the object via reflection |
| **Frida: Hook all overloads** | Uses `.overloads.forEach()` to hook every overloaded variant |

### Field Operations (right-click a field)

| Menu Item | Description |
|---|---|
| **Frida: Read field value** | Uses `Java.choose()` to find all instances and logs the field value |
| **Frida: Modify field value** | Sets a new value on the field for all instances (static fields handled automatically) |

### Smart Features

- **Real parameter names** — extracted from jadx's decompiled source (e.g. `pin` instead of `string0`)
- **Bracket notation** — uses `this["methodName"]()` matching jadx's built-in FridaAction
- **`send()` output** — works reliably with objection and other Frida clients
- **Auto-overload detection** — automatically switches to `.overloads.forEach()` when the method has overloaded variants
- **Void method handling** — skips return value logging for void/constructor methods
- **`Java.perform()` wrapper** — every script is wrapped and ready to run

## Install

```bash
# Build from source
gradle build

# Copy to jadx plugins directory
cp build/libs/frida-copy.jar ~/.jadx/plugins/
```

Or install system-wide:

```bash
cp build/libs/frida-copy.jar /usr/share/jadx/plugins/
```

Restart jadx-gui after installing.

## Usage

1. Open an APK/DEX in jadx
2. Navigate to a method or field in the decompiled code
3. Right-click on the method/field name
4. Select a Frida action from the popup menu
5. The script is copied to your clipboard — paste it into your Frida session

## Example

Right-click `checkPin` → **Frida: Modify arguments**:

```js
Java.perform(function() {
var MainActivity = Java.use("asvid.github.io.fridaapp.MainActivity");
MainActivity["checkPin"].implementation = function (pin) {
  send(`MainActivity.checkPin is called: pin=${pin}`);
  pin = "CHANGE_ME";  // <-- EDIT THIS VALUE
  send("[modify] pin=" + pin);
  var ret = this["checkPin"](pin);
  send("MainActivity.checkPin result=" + ret);
  return ret;
};
});
```

Edit `"CHANGE_ME"` to `"1234"`, paste into Frida/objection, and the method will always receive `"1234"` regardless of what the app sends.

## Requirements

- [jadx](https://github.com/skylot/jadx) 1.5.x
- Java 11+
