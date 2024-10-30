# PII Sniffer - Burp Suite Extension

**PII Sniffer** is an extension for Burp Suite developed to detect sensitive personal information (PII) in intercepted HTTP responses. The extension identifies **CPFs** (Brazilian individual taxpayer registry numbers), **phone numbers**, **important dates** (such as birthdates), and **credit card numbers**, making it easier to identify potential personal data leaks.

## Features

- Detects and validates CPFs in HTTP responses.
- Searches and lists phone numbers.
- Detects important dates in DD/MM/YYYY and MM/DD/YYYY formats.
- Identifies possible credit card numbers, validated using the Luhn algorithm.
- Generates reports on detected PII occurrences, allowing for a detailed analysis of potential data leaks.

## Installation

### Requirements

- [Burp Suite](https://portswigger.net/burp) - Community or Professional Version
- [Jython Standalone](https://www.jython.org/download) - Required to support Python extensions in Burp Suite

### Installation Steps

1. **Download the extension**: Clone or download this repository to get the `PII_Sniffer.py` file.
2. **Set up Jython in Burp**:
   - In Burp Suite, go to **Extension > Settings**.

     ![](images/pii_sniffer_extensions.png)
   
   - In the **Python Environment** section, set the path to the downloaded Jython Standalone file (e.g., `jython-standalone-2.7.4.jar`).

     ![](images/pii_sniffer_pt1.png)

3. **Load the extension**:
   - Go to **Extender > Extensions**.
   - Click on **Add**.

     ![](images/pii_sniffer_add.png)
   
   - Select **Extension Type: Python**.
   - In **Extension file**, select the `PII_Sniffer.py` file.

     ![](images/pii_sniffer_final.png)
     
5. **Installation Confirmation**:
   - A confirmation message (“PII Sniffer, Installation OK!!!”) should appear in Burp Suite’s output tab.

     ![](images/pii_sniffer_instalation_ok.png)

## Usage

1. **Intercept and analyze HTTP traffic** with Burp Suite active.
2. **Check the Output**:
   - The extension automatically analyzes HTTP responses for CPFs, phone numbers, important dates, and credit card numbers.
   - When a valid match is found, such as a CPF, phone number, date, or credit card number, it will be displayed in the output log.
3. **Results**:
   - The extension displays detected CPFs, phone numbers, dates, and credit card numbers, allowing the analyst to verify potential personal data leaks.

     ![](images/pii_sniffer_result.png)

Each identified item is validated and displayed, providing a comprehensive diagnosis of potential personal data leaks.

## Contributions

Contributions are welcome! Feel free to fork the project, open pull requests, or report issues.

---

**Note**: This extension is intended for ethical use only. Always obtain permission before testing and analyzing third-party data. The user is solely responsible for any misuse of this tool.
