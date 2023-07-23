# Serpent Cipher Encryption/Decryption Application

This software application is used to implement the SERPENT Cipher in encrypting and decrypting individual columns in CSV files. It is implemented using Flask, Python, HTML, and CSS.

## How the Application Works

1. Run the Software Application on Local Machine:
   - After setting up the necessary environment and dependencies, run the `server.py` file on your local machine terminal. This will start the web server.

2. Select Encryption or Decryption:
   - Upon opening the application in the web browser, you will be prompted to choose whether you want to perform encryption or decryption.

3. Data Encryption:
   - If you select Data Encryption, you will be redirected to the SERPENT Encryption page.
   - Upload a CSV file: Select the CSV file that you want to encrypt. The application will prompt you to upload the file.
   - Enter the Key: Provide a key in hex digits for encryption purposes.
   - Select the Column: Specify the column name that you want to encrypt.
   - Perform Encryption: The Serpent Cipher implementation will encrypt the selected column and update the CSV file with the encrypted column.
   - Download the Updated CSV File: After encryption, you can press the download button to save the updated CSV file with the encrypted data to your local machine.

4. Data Decryption:
   - If you select Data Decryption, you will be redirected to the SERPENT Decryption page.
   - Enter the Key: Provide the key that you used to encrypt the file.
   - Upload the Encrypted CSV File: Select the encrypted CSV file that you want to decrypt.
   - Select the Column: Specify the column name that you want to decrypt.
   - Perform Decryption: The Serpent Cipher implementation will decrypt the selected column and update the CSV file with the decrypted column.
   - Download the Decrypted CSV File: After decryption, the application will automatically download the decrypted CSV file to your local machine.

## Use Cases

This software application can be used in various scenarios where only specific columns of information need to be hidden or protected, while the rest of the data can be shared openly. One such example is in hospitals, where details of patients can be encrypted (such as personal identification information) while sharing other non-sensitive data like diseases, symptoms, etc., with authorized personnel. This helps protect the privacy of the patients and optimizes database storage by using the same file for multiple purposes.

## Running the Application

To run the application, follow these steps:

1. Install Dependencies: Make sure you have Python, Flask, and the necessary libraries installed. You can install the required dependencies using `pip`.

2. Run the Server: Open your command prompt or terminal, navigate to the project folder containing `server.py`, and run the following command:

   ```
   python server.py
   ```

3. Access the Web Application: Once the server is running, open your web browser and access the application at the specified URL (`http://127.0.0.1:5000/`).

4. Follow the Steps: Follow the on-screen instructions to perform encryption or decryption as per your requirement.

### Note:

   - Ensure the CSV file has a column name and well-structured data without symbols.
   - Enter the column name accurately to avoid errors.
   - Avoid using symbols in column values for proper encryption/decryption.
   - Perform a backup of the original CSV file before encryption/decryption.
   - This application is intended for scenarios where specific columns need privacy.
