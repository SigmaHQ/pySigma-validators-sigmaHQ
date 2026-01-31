# 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Adding Validators**:
   - Follow the existing `Sigmahq[Category]Validator` naming pattern
   - Implement a clear docstring explaining the validation purpose
   - Add comprehensive test cases in `/tests/sigmahq/[category]`

2. **Development Setup**:
   ```bash
   git clone https://github.com/SigmaHQ/pySigma-validators-sigmaHQ.git
   cd pySigma-validators-sigmaHQ
   poetry install
   ```

3. **Testing**:
   Run the full test suite with coverage:
   ```bash
   poetry pytest
   ```

4. **Code Style**:
   - Follow existing Python style (PEP 8)
   - Use type hints where appropriate
   - Maintain consistent docstring formatting
