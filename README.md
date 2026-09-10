# Metadata Decryptor

Heuristic-based IL2CPP metadata reconstruction tool for Standoff 2.

The tool attempts to reconstruct a valid global-metadata.dat header from embedded metadata found inside libunity.so

# Requirements

Run in Terminal:

```bash
pip install -r requirements.txt
```

# Usage

```bash
python main.py --libunity path/to/libunity.so --output global-metadata.dat
```

# Credits

Telegram: [SxNews](https://t.me/SxNews1) Discord: experienceinmymind

Thanks to [Michel-M-Code](https://github.com/Michel-M-code)

Inspired by [Metadata-Decryptor](https://github.com/Michel-M-code/Metadata-Decryptor)

# Dev Notes

I haven't implemented all the functionality yet, but I may do so in the future.

Known reordered structs:

<ul>
    <li>Il2CppTypeDefinition</li>
    <li>Il2CppImageDefinition</li>
    <li>Il2CppGlobalMetadataHeader</li>
    <li>Il2CppCodeRegistration</li>
    <li>Il2CppCodeGenModule</li>
    <li>Il2CppMetadataRegistration</li>
</ul>

If you have any questions or bug reports, ask in discord or create an issue.

# Disclaimer

This project is intended for research, reverse engineering, and educational purposes.
