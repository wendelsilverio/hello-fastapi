# hello-fastapi

Hello world with the resources needed to build a real REST service.

## 🤖 Development

The API can be run in _Development_ mode via the `py main.py` on _Command Prompt_.

## 🧪 Tests

All tests can be Run/Debug `pytest for tests` on _Pycharm_ or `pytest` on _Command Prompt_.

To see the coverage report, run `pytest --cov --cov-report=html:cov_report & cov_report\index.html` on _Command Prompt_.

> Coverage plugin only works with PyCharm Professional

## 📋 Activity List

### Setup

- [ ] Install Python
- [ ] Setup virtual environment

### Development

- [ ] API Router by feature
- [X] Authentication with JWT
- [X] Settings to static files
- [X] OpenAPI version from pyproject.toml
- [ ] Debug mode on PyCharm

### Testing

- [X] Unit test example with pytest
- [X] Coverage report

### Project Structure

- [X] src and tests folder layout
- [ ] gitignore to JetBrains IDE

## 📜 Changelog

You can find the changelog for this project in the [CHANGELOG.md](CHANGELOG.md) file.

## 🛠️ Technology Stack

- **[Python](https://www.python.org/)**: A programming language that lets you work quickly and integrate systems more effectively.
- **[FastAPI](https://fastapi.tiangolo.com/)**: A high-performance framework for building APIs with Python, easy to learn and fast to code.
- **[PyCharm Community](https://www.jetbrains.com/pycharm/)**: An IDE for Python development, suitable for data science and web development.
- **[Windows 11 Home Edition](https://www.microsoft.com/en-us/windows/windows-11)**: The latest version of the Windows operating system, offering enhanced features and performance.

## 📁 Project Structure

The project structure is organized as follows:

- **assets/**: Contains static files and other resources used by the application.
- **resources/**: Contains additional resources and documentation for the project.
- **src/**: Contains the source code of the application.
- **tests/**: Contains the test cases for the application.
- **.gitignore**: Specifies files and directories to be ignored by git.
- **CHANGELOG.md**: Contains a log of all changes made to the project.
- **CODE_OF_CONDUCT.md**: Outlines the standards for behavior expected from contributors.
- **CONTRIBUTING.md**: Provides guidelines for contributing to the project.
- **LICENSE**: Contains the license information for the project.
- **main.py**: The entry point of the application, where the FastAPI app is created and configured.
- **pyproject.toml**: Contains project metadata and configuration for tools.
- **README.md**: Provides an overview and documentation of the project.

## 🤝 Contributing

We welcome contributions from the community. Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.