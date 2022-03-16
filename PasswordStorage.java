import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class PasswordStorage {
  //Static varibles for the mac and encode keys / salt
  private static SecretKey MACSKey;
  private static SecretKey EncSKey;
  private static byte[] MACSalt;
  private static byte[] EncSalt;
  //Stores the byte arrays for the all data being read
  private byte[] PrevHMAC;
  private byte[] CurHMAC;
  private byte[] Enc;
  private byte[] EncData;
  private byte[] Dec;
  private byte[] data;
  private byte[] HMACSaltEnc;
  private byte[] AppPassData;
  private byte[] MLData;
  private byte[] masterPassBytes;
  private byte[] Hmac;
  //String array for storing read appPasswordPairs from.
  private String[] appPasswordPairs;
  //Different strings for storing data read from the user and storage files
  private String appName;
  private String password;
  private String dataText;
  private String appPassword;
  private String masterPassword;
  //Used for reading / creating the files / paths which store the
  //appPasswordPairs and MasterPassword
  private File appPasswords;
  private File masterLogin;
  private Path appPasswordPath;
  private Path masterPath;
  //A Scanner for reading user input
  private Scanner sc;

  //A method which provides a user the ability to be able to generate and save
  //a password for a given application
  public void registerAppPassword(){
      System.out.println("");
      //Finds the path for the appPassword.PassStore file
      appPasswordPath = Paths.get("./appPasswords.PassStore");
      //Stores a varible for determining the length of a generated password
      int Length = 0;
      try{
        //Sets up a scanner for reading user input
        sc = new Scanner(System.in);
        //Prompts the user to enter the master password
        System.out.println("Enter Master Password for Performing Add Password Operation: ");
        //Reads user input to get the master password from
        //the user for authentication
        masterPassword = sc.next();
        //Performs the authenticateUserAndIntegrity method using the given master password
        authenticateUserAndIntegrity(masterPassword);
        //Gets the Application Name from the user
        System.out.println("");
        System.out.println("Application Name: ");
        appName = sc.next();
        String newline = System.getProperty("line.separator");
        //Checks if the appName contains any illegal characters used for seperation
        //(~ or `)
        if(appName.contains("~") || appName.contains("`")){
          System.out.println("");
          System.out.println("Error! App Name provided includes invalid characters (~ or `)");
          return;
        }
        //Read all the data from the given appPasswords.PassStore file
        data = Files.readAllBytes(appPasswordPath);
        //Read only the encripted data by excluding the HashMac and Salt
        EncData = Arrays.copyOfRange(data, 320, data.length);
        //Performs the decription for the section of encripted data
        //through the decrypt method and the EncSKey secret key
        Dec = dec(EncSKey, EncData);
        //Reads the decoded data passed in as readable text
        dataText = new String(Dec, "UTF-8");
        //Performs a check to see if the app name provided already exsists
        boolean match = checkAppName(appName, dataText);
        //if one already exists (Match = true)
        if (match != false){
            //If does exist then tell the user that they need to delete the app
            //password before adding a new one
            System.out.println("");
            System.out.println("Error! Provided app name already exists! ");
            System.out.println("Please select DEL function to remove the previous record before adding a new record.");
            //Returns back to the userOptions
            return;
        }
        //While the length has not been assigned, loop until Length does not equal 0
        while (Length == 0){
            //Prompts the user to enter a value within the given range
            System.out.println("");
            System.out.println("Please enter a length for the generated password (Between 8 and 80): ");
            //If the user input value is a int
            if(sc.hasNextInt()) {
              Length = sc.nextInt();
              //Checks if the size is within the range
              if((Length >= 8 && Length <= 80) != true){
                //If not, give the user an error message and set length back to 0
                System.out.println("");
                System.out.println("Error! Value entered is not within the required range ");
                Length = 0;
              }
            }
            //Otherwise give an error to let the user know to only enter numeric digits
            else{
              System.out.println("");
              System.out.println("Error! Please enter only numeric digits: ");
              sc.next();
            }
        }
        //Sets up a instance of the password generator module
        PasswordGenerator pg = new PasswordGenerator();
        //Assigns the new created password as the method call from the function
        //CreatePassword(Length) in PasswordGenerator module
        password = pg.CreatePassword(Length);
        //Make the new appPasswordPair through the following format:
        //<APPNAME>~<Password>`
        appPassword = appName + "~" + password + "`";
        //Reads the byte data from the the appPassword string and then
        //Put the data at the end of the unencripted data
        byte[] dataInUTF8 = appPassword.getBytes("UTF-8");
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(Dec);
        os.write(dataInUTF8);
        byte[] newData = os.toByteArray();
        //Perform encrypt on the updated data via the encript method and
        //generates a HashMac through the Hmac method
        Enc = enc(EncSKey, newData);
        Hmac = genHMAC(MACSKey, Enc);
        //Performs the concatenate operation for producing the HMACSaltEnc
        os = new ByteArrayOutputStream();
        os.write(MACSalt);
        os.write(Hmac);
        os.write(Enc);
        HMACSaltEnc = os.toByteArray();
        //Attempts to write all the updated data out to the appPasswords.PassStore
        FileOutputStream output = new FileOutputStream("appPasswords.PassStore");
        output.write(HMACSaltEnc);
        output.close();
        os.close();
        //Prints out the result to the user
        System.out.println("");
        System.out.println("Successfully added generated password: " + password + " for application: " + appName);
      }
      catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException |  NoSuchProviderException | BadPaddingException |
      InvalidKeyException | InvalidParameterSpecException | InvalidAlgorithmParameterException | IOException | IllegalBlockSizeException e){
          //Prints out the exception message
          System.out.println(e.getMessage());
      }
  }

  //A method which allows for a user to delete a AppPassword record, attempts
  //to find a match given user inputted appName and Password
  public void deleteAppPassword() {
      try{
        System.out.println("");
        //Sets up a scanner for reading user input
        sc = new Scanner(System.in);
        //Prompts the user to enter the master password
        System.out.println("Enter Master Password for Performing Delete Operation: ");
        //Reads user input to get the master password from
        //the user for authentication
        masterPassword = sc.next();
        //Performs the authenticateUserAndIntegrity method using the given master password
        authenticateUserAndIntegrity(masterPassword);
        //Gets the data byte array from the appPasswords.PassStore
        appPasswordPath = Paths.get("./appPasswords.PassStore");
        data = Files.readAllBytes(appPasswordPath);
        //Prompts the user to enter the application name that they are wanting to
        //generate / store a password for
        System.out.println("");
        System.out.println("Application Name: ");
        //Sets up a scanner for reading in the app name and current password
        sc = new Scanner(System.in);
        //Reads the app name from the scanner
        appName = sc.next();
        //Read only the encripted data by excluding the HashMac and Salt
        EncData = Arrays.copyOfRange(data, 320, data.length);
        //Performs the decription for the section of encripted data
        //through the decrypt method and the EncSKey secret key
        Dec = dec(EncSKey, EncData);
        //Reads the decoded data passed in as readable text
        dataText = new String(Dec, "UTF-8");
        //Performs a call of method appName to see if a match was found
        boolean match = checkAppName(appName, dataText);
        //If match returns true
        if (match) {
            //Reads in the decoded data as UTF-8 text and splits it at the delimiter
            dataText = new String(Dec, "UTF-8");
            appPasswordPairs = dataText.split("`");
            //Goes through a loop of each of the pairs to try and find
            //one which contains the appname + password pair
            for (int i = 0; i < appPasswordPairs.length; i++) {
                //Splits the AppName password pair at the delimiter ~
                String[] valuesSplit = appPasswordPairs[i].split("~");
                //If a match was found for the given appName
                if (valuesSplit[0].equals(appName)) {
                    //Changes that appPasswordPairs value to "" to remove it
                    appPasswordPairs[i] = "";
                    //Create a updated string with the prevously removed pair taken out
                    String newAccList = "";
                    for (int j = 0; j < appPasswordPairs.length; j++) {
                        //If a removed index is encountered ( = "") skip it
                        if (appPasswordPairs[j].equals("") != true) {
                            newAccList += appPasswordPairs[j] + "`";
                        }
                    }
                    //Once the updated newAccList is created, convert it into a byte array
                    byte[] updatedData = newAccList.getBytes("UTF-8");
                    //Encrypts the data through the encrypt function
                    Enc = enc(EncSKey, updatedData);
                    //Creates the updated HashMac and combines the salt, HMAC
                    //and Ecrypted data
                    Hmac = genHMAC(MACSKey, Enc);
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    os.write(MACSalt);
                    os.write(Hmac);
                    os.write(Enc);
                    HMACSaltEnc = os.toByteArray();
                    //Creates a file output stream to write data to
                    FileOutputStream fos = new FileOutputStream("appPasswords.PassStore");
                    fos.write(HMACSaltEnc);
                    //Closes the file output stream
                    fos.close();
                    System.out.println("");
                    System.out.println("Successfully removed: " + appName);
                    return;
                }
            }
        }
        //Give the user a message to let them know that no matches were found for the given app
        else {
            System.out.println("");
            System.out.println("No matches were found for the given app name: " + appName);
        }
      }
      catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | BadPaddingException | NoSuchPaddingException |
      IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidParameterSpecException | InvalidKeySpecException | IOException e){
          //Prints out the exception message
          System.out.println(e.getMessage());
      }
  }
    //A method which is used to search a given app name in the list of data
    //Returns true if a match is found, false if not
    public boolean checkAppName(String appName, String dataString) throws UnsupportedEncodingException {
        //Splits the dataText at the pair delimitor "`"
        appPasswordPairs = dataString.split("`");
        //search through appPasswordPairs
        for (String appPassswordPair : appPasswordPairs) {
            //Splits the value at the value delimitor ~
            String[] valuesSplit = appPassswordPair.split("~");
            //If a match was found return true
            if (valuesSplit[0].equals(appName)) {
                return true;
            }
        }
        //If no match was found then return false
        return false;
    }
    public void authenticateUserAndIntegrity(String masterPassword) throws
            IOException,NoSuchAlgorithmException,
            NoSuchProviderException,InvalidKeyException,NoSuchPaddingException,
            InvalidKeySpecException,IllegalBlockSizeException,InvalidParameterSpecException,
            BadPaddingException,InvalidAlgorithmParameterException {
        //Trys to open the given appPasswords and masterLogin files
        appPasswords = new File("./appPasswords.PassStore");
        masterLogin = new File("./masterLogin.PassStore");
        //Creates a message digest using SHA-512 (For hashing)
        MessageDigest mda = MessageDigest.getInstance("SHA-512");
        //If either of the files are not present, then use the passed in master
        //password to setup new .PassStore files
        if ((appPasswords.exists() && masterLogin.exists()) != true) {
            //Provides a message to the user to let them know of the operations
            //of setting up new .PassStore files with the given master password
            System.out.println("");
            System.out.println("masterLogin.PassStore or appPasswords.PassStore does not exist");
            System.out.println("Creating new setup files with given Master Password");
            //Sets up files for the newly created masterLogin and appPasswords
            masterLogin = new File("./masterLogin.PassStore");
            appPasswords = new File("./appPasswords.PassStore");
            //Sets up paths for attempting to delete old intances of
            //the appPasswords or masterLogin .PassStore
            appPasswordPath = Paths.get("./appPasswords.PassStore");
            Files.deleteIfExists(appPasswordPath);
            masterPath = Paths.get("./masterLogin.PassStore");
            Files.deleteIfExists(masterPath);
            //Creates both the files setup
            masterLogin.createNewFile();
            appPasswords.createNewFile();
            //Gets the bytes from the passed in masterPassword
            masterPassBytes = masterPassword.getBytes();
            //Creates random salt for the encode
            //and decode through generating a new byte[256] through secure random
            SecureRandom rand = new SecureRandom();
            EncSalt = new byte[256];
            MACSalt = new byte[256];
            rand.nextBytes(EncSalt);
            rand.nextBytes(MACSalt);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(EncSalt);
            os.write(masterPassBytes);
            byte[] saltedPassword = os.toByteArray();
            //Creates the Hash and the Salt for adding to the masterLogin.PassStore
            byte[] HashBytes = mda.digest(saltedPassword);
            os = new ByteArrayOutputStream();
            os.write(EncSalt);
            os.write(HashBytes);
            byte[] saltAndHash = os.toByteArray();
            //Creates a file output stream for wrting the masterLogin.PassStore
            FileOutputStream fosM = new FileOutputStream("masterLogin.PassStore");
            //Writes the salt and hash data
            fosM.write(saltAndHash);
            //Closes the file output stream
            fosM.close();
            //Creates a Secret Key for both the MAC and Encode data,
            //utilises the MACSalt and EncSalt for salting them.
            MACSKey = genKey(masterPassword, MACSalt);
            EncSKey = genKey(masterPassword, EncSalt);
            //Reads all the data from the appPasswordPath and perform
            //the encription operation on that data, generate a HashMacc.
            AppPassData = Files.readAllBytes(appPasswordPath);
            Enc = enc(EncSKey, AppPassData);
            Hmac = genHMAC(MACSKey, Enc);
            //Combines all the data together with one another
            os = new ByteArrayOutputStream();
            os.write(MACSalt);
            os.write(Hmac);
            os.write(Enc);
            HMACSaltEnc = os.toByteArray();
            //Creates a file output stream for writing the appPasswords.PassStore to
            FileOutputStream fosA = new FileOutputStream("appPasswords.PassStore");
            //Writes the all the data to the file
            fosA.write(HMACSaltEnc);
            //Closes the file output stream before returning
            fosA.close();
            return;
        }
        //Otherwise if both files are present, attempt to authenticate the user
        //with the provided masterPassword
        else {
            //Gets all data from the masterLogin.PassStore file
            masterPath = Paths.get("./masterLogin.PassStore");
            byte[] masterLoginData = Files.readAllBytes(masterPath);
            //Gets the 256 bits of salt from the data array
            byte[] salt = Arrays.copyOf(masterLoginData, 256);
            masterPassBytes = masterPassword.getBytes();
            //concatenate the salt and the password then HashBytes it
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(salt);
            os.write(masterPassBytes);
            byte[] saltedPassword = os.toByteArray();
            byte[] hashed = mda.digest(saltedPassword);
            os = new ByteArrayOutputStream();
            os.write(salt);
            os.write(hashed);
            os.close();
            byte[] unsaltedPassword = os.toByteArray();
            //If the entered password does not match the password then
            //give the user a message and quit the program
            if (Arrays.equals(masterLoginData, unsaltedPassword) != true){
                System.out.println("Incorrect Master Password Entered! Now Exiting Program");
                System.exit(0);
            }
            //Gets all the data from the master and appPassword files
            masterPath = Paths.get("./masterLogin.PassStore");
            MLData = Files.readAllBytes(masterPath);
            appPasswordPath = Paths.get("./appPasswords.PassStore");
            AppPassData = Files.readAllBytes(appPasswordPath);
            //Extracts the salt data from the master and appPassword files
            MACSalt = Arrays.copyOf(AppPassData, 256);
            EncSalt = Arrays.copyOf(MLData, 256);
            //Creates a Encription Secret key and Mac Secret key using the master
            //password and each salt for each.
            EncSKey = genKey(masterPassword, EncSalt);
            MACSKey = genKey(masterPassword, MACSalt);
            //Reads the stored HashMac from the data
            PrevHMAC = Arrays.copyOfRange(AppPassData, 256, 320);
            //generates a new hash mac to check that they match the prevous one
            Enc = Arrays.copyOfRange(AppPassData, 320, AppPassData.length);
            CurHMAC = genHMAC(MACSKey, Enc);
            //If the Hash MACs do not match each other
            if (Arrays.equals(PrevHMAC, CurHMAC) != true) {
                //Provides user with a error message and instructions for if they
                //want to continue or remove tampered files and quit
                System.out.println("");
                System.out.println("Caution! Password Storage Files Have Been Tampered With!");
                System.out.println("Type Y to continue or N to remove tampered files and quit");
                //Sets up a scanner for reading in user input
                sc = new Scanner(System.in);
                //Reads in the line
                String userInput = sc.nextLine().toUpperCase();
                //Determines what option the user has entered
                //If the user has selected Y then continue
                if(userInput.equals("Y")){
                    return;
                }
                //If the user has selected N then delete files and exit
                else if (userInput.equals("N")){
                    System.out.println("Removing Tampered Files...");
                    //Attempts to delete the files if they exist
                    appPasswordPath = Paths.get("./appPasswords.PassStore");
                    Files.deleteIfExists(appPasswordPath);
                    masterPath = Paths.get("./masterLogin.PassStore");
                    Files.deleteIfExists(masterPath);
                }
                //Any other input, give the user a error message and quit without
                //removing files
                else{
                    System.out.println("");
                    System.out.println(userInput + " is a invalid input! Will exit wihout removing files");
                }
                System.out.println("");
                System.out.println("Now Exiting Program");
                System.exit(0);
            }
            return;
        }
    }

    //An encription method for performing AES Encription in CTR mode with NoPadding
    public static byte[] enc(SecretKey key, byte[] in) {
        try{
            //Sets the cypher to be AES/CTR/NoPadding
            Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
            //Generates a IV through utilising secure random
            SecureRandom rand = new SecureRandom();
            byte[] iv = new byte[aes.getBlockSize()];
            //Assigns the values to the iv and creates a IvParameterSpec
            rand.nextBytes(iv);
            IvParameterSpec ivP = new IvParameterSpec(iv);
            //Performs the encryption function
            aes.init(Cipher.ENCRYPT_MODE, key, ivP);
            byte[] enc = aes.doFinal(in);
            //Adds the iv and the enc data together with one another in
            //a byte array
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(iv);
            os.write(enc);
            return os.toByteArray();
        }
        catch(NoSuchAlgorithmException | BadPaddingException  | InvalidKeyException | IOException |
                IllegalBlockSizeException | NoSuchPaddingException | InvalidAlgorithmParameterException e){
            //Prints out the exception message
            System.out.println(e.getMessage());
            return null;
        }

    }

    //A method for performing AES Decryption in CTR mode with NoPadding
    public static byte[] dec(SecretKey key, byte[] in) {
        try{
            //Sets the cypher to be AES/CTR/NoPadding
            Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
            //Retreves the iv from the passed in input through reading
            //the first bites upto the aes.getBlockSize()
            byte[] iv = new byte[aes.getBlockSize()];
            iv = Arrays.copyOf(in, iv.length);
            //Creates a IvParameterSpec using the retreved iv bytes
            IvParameterSpec ivP = new IvParameterSpec(iv);
            //Gets the data from the input (Everything after the iv)
            byte[] enc = Arrays.copyOfRange(in, iv.length, in.length);
            //Initilises the Cypher to be in decript mode and returns the decryption
            //through performing .doFinal
            aes.init(Cipher.DECRYPT_MODE, key, ivP);
            return aes.doFinal(enc);
        }
        catch(NoSuchAlgorithmException | BadPaddingException  | InvalidKeyException |
            IllegalBlockSizeException | NoSuchPaddingException | InvalidAlgorithmParameterException e){
            //Prints out the exception message
            System.out.println(e.getMessage());
            return null;
        }
    }

    //A method for generating a Hash Based Message Authentication Code
    public static byte[] genHMAC(SecretKey key, byte[] in){
        try{
            //Use HmacSHA512 for the Mac Instance and Initilises it with
            //the passed in a secret key
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(key);
            //Returns the HMAC through performing doFinal on the input
            return mac.doFinal(in);
        }
        catch(NoSuchAlgorithmException | InvalidKeyException e){
            //Prints out the exception message
            System.out.println(e.getMessage());
            return null;
        }
    }

    //A method for generating a SecretKey using a passed in master password and
    //byte array for salting
    public static SecretKey genKey(String password, byte[] salt) {
        try{
            //Sets up the SecretKeyFactory to use Password-Based Key Derivation Function 2
            //and Hmac + SHA256
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            //Generates a new keyspec using the given password string and salt
            KeySpec ks = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            //Creates a secret key using the SecretKeyFactory created keyspec
            SecretKey sk = factory.generateSecret(ks);
            //Returns a SecretKeySpec
            return new SecretKeySpec(sk.getEncoded(), "AES");
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e){
            //Prints out the exception message
            System.out.println(e.getMessage());
            return null;
        }
    }
}
