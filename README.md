# Serpentcipher

This Software application is used to implement SERPENT Cipher in encrypting and decrypting individual columns in CSV files.It is implemented with the help of Flask,Python,HTML,CSS.

On running the software application on local machine,the html file opens on the webserver.We first select whether we want to perform Encryption or Decryption.On selecting Data Encryption,the web page is redirected to SERPENT Encrpytion in which we upload a CSV file,a key which is in hex digits along with the Column name.On uploading,the Serpent Cipher implementation will encrypt the selected column and update the CSV file with encrypted column. On pressing the download button the updated CSV file will directly download into the local machine.The same happens with Data Decryption where we enter the key we used to encrypt the file along with the encrypted file and the column to be decrypted. The decrypted file will automatically download onto the local machine.

This Software application can be used in places where only few columns of information has to be hidden so that it is multi-applicable.One such example is Hospital where details of patients can be encrypted and the remaining data regarding diseases,symptoms,etc.. can be shared with others.This helps in protecting the privacy of the patients and also decrease in database storage as same file can be used for all purposes.
