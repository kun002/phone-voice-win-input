# Contributing

Contributions are welcome.

## Development

The core service uses the Python standard library. The optional desktop GUI
uses PySide6.

```powershell
python -m pip install -r .\requirements-gui.txt
python .\phone_voice_win_input.py --self-test
.\start.ps1 -Gui
```

Before opening a pull request:

1. Run the self-test.
2. Test local and remote input targets when changing Windows injection logic.
3. Do not commit `.phone_voice_token`, `.phone_voice_settings.json`, generated
   QR images, private IP addresses, or dictated text.
4. Keep phone-side controls minimal and put configuration in the desktop UI.