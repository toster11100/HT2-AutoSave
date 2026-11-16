[English](README.md) | [Русский](README_RU.md)

# HT2 AutoSave 1.1.0

AutoSave uses the game's native save routine after selected game events and during active play. It is an ASI plugin for *Hard Truck 2: King of the Road*.

## Features

- Saves after cargo pickup and successful delivery, a rewarded circuit-race win, vehicle purchase, and driver hire.
- Optional active-play interval; the default is 10 minutes.
- Keeps three autosave slots by default (`autosave_1` newest); other manual slots are not rotated.
- Defers pending saves while paused, in menus, or while the game is unfocused; merges multiple events into one request.
- Creates `plugins/HT2_AutoSave.ini` when absent; existing files are not overwritten.
- Pager messages: Russian, English, French, German, and Spanish.

## Settings

The INI uses the `[AutoSave]` section. It is created on first entry to the game world. The file is read once per game process; restart the game after changing it.

| Key | Default | Meaning |
| --- | --- | --- |
| `Enabled` | `true` | Enable the mod |
| `OnCargoPickup` | `true` | Save after cargo pickup |
| `OnCargoDelivery` | `true` | Save after successful delivery |
| `OnRaceVictory` | `true` | Save after a rewarded circuit-race win |
| `IntervalEnabled` | `true` | Enable the active-play timer |
| `IntervalMinutes` | `10` | Active-play interval, 1–1440 minutes |
| `MaxAutoSaves` | `3` | Autosave slots, 1–99 |
| `ShowNotification` | `true` | Show pager notifications |
| `OnVehiclePurchase` | `true` | Save after a successful vehicle purchase |
| `OnDriverHire` | `true` | Save after a successful driver hire |

Boolean values accept `true`/`false`, `yes`/`no`, `on`/`off`, and `1`/`0`. Missing keys use built-in defaults; an invalid value is replaced by the default for that key. The mod creates the INI only if it does not exist and does not rewrite existing bytes, comments, or extra keys. Read, create, or write failures use defaults and are reported in the status file. When upgrading from an older package that installed the INI as a managed Workshop file, preserve its settings separately because a synchronizer may still track it.

## Supported game versions

- `KOTR81`: Russian game version 8.1, verified against the reference SHA-256 below.
- `KOTR13`: international *King of the Road* version 1.3, verified against the reference SHA-256 below. Known English, French, German, and Spanish executables share this profile only where their SHA-256 matches the verified reference.
- Modified Game Core 8.2.

An identical version number alone does not establish compatibility. The GOG build has not been individually verified; no GOG compatibility is claimed unless its executable passes the mod's checks and is tested.

## Installation and removal

Requires Windows, a supported 32-bit game executable, and a compatible ASI Loader. Close the game and back up the `.pl1` profile before first use. Copy `plugins/HT2_AutoSave.asi` from the ZIP into the game's `plugins` directory. When upgrading from an experimental build, remove `HT2_AutoSave_Experimental.asi`; install only one AutoSave ASI.

To uninstall, close the game and remove `plugins/HT2_AutoSave.asi`. The mod does not remove `HT2_AutoSave.ini` or autosave slots; retain or remove those yourself.

## Save behavior, limitations, and diagnostics

`autosave_1` is newest, followed by `autosave_2`, and so on. The order persists across restarts. Only slots named `autosave_N` are rotated; other manual slots are left alone. User-edited autosave slots are not protected from rotation. The native save format is unchanged and all slots share the profile's `.pl1` file, so a failed write may affect the whole profile.

Slot rotation is not atomic. An error can leave an incomplete sequence and disables further automatic attempts until the next game restart. The native save return value and pager notification do not prove that data reached disk. Back up saves before first use. A transition from the old circular 0.1.2 ordering completes after enough new autosaves have been made.

After entering the game world, check `HT2_AutoSave_Status.ini`. `Result=Ready` and `Version=1.1.0` indicate initialization. `IniStatus=Created` or `Existing` with `IniError=00000000` indicates normal configuration access. `ReadFailed`, `CreateFailed`, or `WriteFailed` means defaults are used. `SignatureConflict` or `PatchFailed` disables the mod. `RotationFailed` stops later attempts until restart. A status file may not be created for an unsupported executable.

## Runtime dependencies and compatibility

The game and an ASI Loader are required. AutoSave has no runtime dependency on Tractor Swap, Fleet Upgrade, or another mod. The mod uses the game's native save routine and Win32 APIs; Steam language detection is optional and has a fallback.

## Build from source

Use Python 3.10+ on Windows. The toolchain and tests are pinned in `requirements.txt` and `requirements-test.txt`:

```powershell
python -m pip install -r requirements-test.txt
$env:HT2_BUILD_INPUTS = 'C:\path\outside\the\repository\to\private-game-files'
python build.py --release
python -m unittest discover -s tests -t . -p 'test_*.py' -v
python package_release.py
```

`HT2_BUILD_INPUTS` must point outside this repository and contain:

| File | Expected SHA-256 | Used for |
| --- | --- | --- |
| `KOTR81.exe` | `31fbd1dbbe7706183f09a3688482791255db2bfb557c02675374b96796ce2ebd` | KOTR81 / 8.1 |
| `ModifiedCore82.exe` | `b57eb1e34dd00c6c5270ca42ada931039d9baed488dee5bb33f46ffa2a6097d6` | Modified Game Core 8.2 |
| `KOTR13.exe` | `0df6861c9e67c2a2ae373cff8d765ae41cc76079d8f84b9340e609263edd983f` | KOTR13 / 1.3 reference |
| `ht2ach.dll` | From the local game installation | One Steam-achievement regression test only |

Game files are not included. The AutoSave build is independent of Tractor Swap source code. Generated files stay in the ignored `build-output/` directory. The player installation guide is [`packaging/README.txt`](packaging/README.txt), which is included in the ZIP.

## License and third-party material

Original mod source is licensed under **GPL-3.0-only**; see [`LICENSE`](LICENSE). The license does not apply to the game, Steam, ASI Loader, or third-party tools. Game executables, DLLs, saves, and cover art are not included. The builder reads reference executables locally to generate compatibility signatures; it does not copy them into the repository.

Steam Workshop: [AutoSave 1.1.0](https://steamcommunity.com/sharedfiles/filedetails/?id=3840508411).
