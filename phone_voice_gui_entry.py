"""GUI-only entry point used by the Windows release build."""

from phone_voice_win_input import main


if __name__ == "__main__":
    raise SystemExit(main(["--gui", "--no-qr"]))