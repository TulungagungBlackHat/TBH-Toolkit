# Contributing

1. Fork and create a feature branch.
2. Keep `tbh` dependency-free (Python stdlib only).
3. Run the smoke checks locally:
   ```bash
   python3 -m py_compile tbh
   bash -n install.sh
   python3 tbh doctor
   ```
4. Open a pull request with a clear description.

By contributing you agree your code is released under the MIT license.
