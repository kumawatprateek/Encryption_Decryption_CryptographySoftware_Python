# SecureInfo Windows Software

**SecureInfo** is a Windows application designed to provide robust encryption and decryption capabilities, ensuring the security of various types of files including text, images, audio, and video. It leverages Elliptic Curve Cryptography (ECC) to offer a high level of data security, allowing users to protect sensitive information effectively.

## Table of Contents
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Benefits](#benefits)
- [System Requirements](#system-requirements)
- [Installation Guide](#installation-guide)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Data Flow Diagrams](#data-flow-diagrams)
- [Development Specifications](#development-specifications)
- [Methodology](#methodology)
- [Conclusion](#conclusion)
- [References](#references)

## Project Overview
SecureInfo is developed as a part of a summer training project for the Master of Computer Application (MCA) program at the University of Kota. The software is designed to enhance data security by providing encryption and decryption functionalities for various file types. Users can also hide text within images and password-protect PDFs, adding layers of security to their data.

## Key Features
- **Encryption and Decryption**: SecureInfo supports the encryption and decryption of multiple file types, including text, images, audio, video, and PDFs.
- **ECC Key Generation**: Utilizes Elliptic Curve Cryptography (ECC) for secure and efficient encryption.
- **Simple User Interface**: A user-friendly interface that allows easy navigation and use.
- **Multi-functional Software**: Offers multiple encryption and decryption options in one platform, enhancing efficiency.

## Benefits
- **Security of Data**: Protects various types of data like text, images, PDFs, etc.
- **Data Hiding**: Allows users to hide text data within images, providing an additional layer of confidentiality.
- **User-friendly Interface**: Simplifies the encryption and decryption process for users of all technical levels.

## System Requirements
- **Operating System**: Any Windows OS
- **RAM**: Minimum 1GB
- **Storage**: Sufficient space to store encrypted files and software
- **Software Dependencies**: Python 3.x, Tkinter library, PyCharm IDE (optional)

## Installation Guide
1. **Clone the Repository**: Clone the SecureInfo repository from GitHub or download the ZIP file.
2. **Install Python**: Ensure Python 3.x is installed on your system.
3. **Install Required Libraries**: Install the necessary Python libraries using pip:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Application**: Navigate to the project directory and run the main application file.
   ```bash
   python main_homepage.py
   ```

## Usage
1. **Registration**: New users must register and will be assigned unique ECC keys for encryption and decryption.
2. **Login**: Registered users can log in using their credentials.
3. **Encrypt/Decrypt Files**: Choose the type of file to encrypt or decrypt from the home page.
4. **Hide Text in Image**: Use the specific option to hide text within an image.
5. **Password Protect PDFs**: Secure PDFs by setting a password.

## Screenshots
- **Login Page**: A simple login interface to authenticate users.
- **Home Page**: The main interface with options for different encryption and decryption tasks.
- **Information Menu**: Provides access to various features like text security, image security, etc.

## Data Flow Diagrams
- **Level 0**: Overview of the system's major functions.
- **Level 1**: Detailed flow between different components like Home, Information, Text Secure, etc.
- **Level 2**: In-depth flow including encryption, decryption, and data management.

## Development Specifications
- **Front End**: Tkinter library
- **Back End**: Python 3.x
- **Database**: CSV database to store user information and ECC keys
- **IDE**: PyCharm Community Edition (optional)
- **Operating System**: Windows 10 Pro
- **Hardware Requirements**: 8 GB RAM, 512 GB ROM, i5 7th Gen Processor

## Methodology
The software was developed using the waterfall model, ensuring each phase from requirement gathering to deployment was systematically approached. ECC was chosen for its strength in security while maintaining efficiency in performance.

## Conclusion
SecureInfo is an effective tool for securing various types of information using ECC. It simplifies the process of encryption and decryption and provides additional features like text hiding and PDF protection. The software’s intuitive interface and robust security measures make it a valuable tool for users concerned about data privacy.

## References
- [Types of Encryption](https://rb.gy/c84h2) - Article on Prey Project
- YouTube Channels:
  - [GateSmashers](https://www.youtube.com/@GateSmashers)
  - [5MinutesEngineering](https://www.youtube.com/@5MinutesEngineering)
  - [Rajeshwari Gundla](https://www.youtube.com/@rajeshwarigundla4038)
  - [CodeWithHarry](https://www.youtube.com/@CodeWithHarry)
- [Logo Creation Tools](https://logo.com/), [Adobe Spark](https://www.adobe.com/express/create/logo)

---

This README provides a comprehensive overview of the SecureInfo project, guiding users from installation to usage while highlighting the key features and benefits of the software.
